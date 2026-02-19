#!/usr/bin/env python
"""
V1 API Endpoint Testing Script
==============================
This script tests all V1 API endpoints to verify they're working correctly.

Usage:
    python scripts/test_endpoints.py
    
Make sure the API server is running on http://localhost:8000 first.
"""

import requests
import json
import sys
import os
from datetime import datetime

# Fix Windows console encoding
if sys.platform == 'win32':
    os.system('')  # Enable ANSI escape codes on Windows

BASE_URL = "http://localhost:8000"

# Colors for terminal output (ASCII-compatible)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_header(text):
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}{text}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")


def print_result(name, success, status_code=None, message=None):
    # Use ASCII symbols for Windows compatibility
    status = f"{GREEN}[PASS]{RESET}" if success else f"{RED}[FAIL]{RESET}"
    code_str = f"[{status_code}]" if status_code else ""
    msg_str = f"- {message}" if message else ""
    print(f"  {status} {name} {code_str} {msg_str}")


def test_endpoint(name, method, url, expected_status=200, headers=None, data=None, json_data=None):
    """Test a single endpoint."""
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, data=data, json=json_data, timeout=10)
        else:
            print_result(name, False, message=f"Unknown method: {method}")
            return None

        success = response.status_code == expected_status
        print_result(name, success, response.status_code)
        return response
    except requests.exceptions.ConnectionError:
        print_result(name, False, message="Connection refused - is the server running?")
        return None
    except Exception as e:
        print_result(name, False, message=str(e))
        return None


def get_auth_token():
    """Login and get authentication token."""
    print_header("1. Authentication")
    
    # First, try to login
    response = test_endpoint(
        "POST /auth/login (get token)",
        "POST",
        f"{BASE_URL}/auth/login",
        200,
        data={"username": "admin", "password": "admin123"}
    )
    
    if response and response.status_code == 200:
        try:
            token = response.json()["data"]["access_token"]
            print(f"  {GREEN}-&gt; Token obtained successfully{RESET}")
            return token
        except (KeyError, json.JSONDecodeError):
            print(f"  {RED}-&gt; Failed to parse token from response{RESET}")
    
    return None


def test_health_endpoints():
    """Test health check endpoints."""
    print_header("2. Health & Metrics Endpoints (No Auth Required)")
    
    # Health check
    r = test_endpoint("GET /health", "GET", f"{BASE_URL}/health")
    if r:
        try:
            data = r.json()
            print(f"    -&gt; Status: {data.get('status')}")
            print(f"    -&gt; Components: {list(data.get('components', {}).keys())}")
        except:
            pass
    
    # Liveness probe
    test_endpoint("GET /health/live", "GET", f"{BASE_URL}/health/live")
    
    # Readiness probe
    test_endpoint("GET /health/ready", "GET", f"{BASE_URL}/health/ready")
    
    # Metrics (Prometheus format)
    r = test_endpoint("GET /metrics", "GET", f"{BASE_URL}/metrics")
    if r:
        lines = r.text.split('\n')
        print(f"    -&gt; {len([l for l in lines if not l.startswith('#')])} metrics exposed")
    
    # Metrics (JSON format)
    test_endpoint("GET /metrics/json", "GET", f"{BASE_URL}/metrics/json")


def test_v1_dashboard(token):
    """Test V1 dashboard endpoints."""
    print_header("3. V1 Dashboard Endpoints (Auth Required)")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Dashboard summary
    r = test_endpoint(
        "GET /api/v1/dashboard/summary",
        "GET",
        f"{BASE_URL}/api/v1/dashboard/summary",
        headers=headers
    )
    if r:
        try:
            data = r.json()["data"]
            print(f"    -&gt; Total Events: {data.get('total_events', {}).get('count')}")
            print(f"    -&gt; Active Threats: {data.get('active_threats', {}).get('count')}")
            print(f"    -&gt; Risk Score: {data.get('risk_score', {}).get('score')}")
        except:
            pass


def test_v1_analytics(token):
    """Test V1 analytics endpoints."""
    print_header("4. V1 Analytics Endpoints (Auth Required)")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Timeline - 24h/hour
    r = test_endpoint(
        "GET /api/v1/analytics/timeline?range=24h&bucket=hour",
        "GET",
        f"{BASE_URL}/api/v1/analytics/timeline?range=24h&bucket=hour",
        headers=headers
    )
    if r:
        try:
            data = r.json()["data"]
            print(f"    -&gt; Range: {data.get('range')}, Bucket: {data.get('bucket')}")
            print(f"    -&gt; Data points: {len(data.get('series', []))}")
        except:
            pass
    
    # Timeline - 7d/day
    test_endpoint(
        "GET /api/v1/analytics/timeline?range=7d&bucket=day",
        "GET",
        f"{BASE_URL}/api/v1/analytics/timeline?range=7d&bucket=day",
        headers=headers
    )
    
    # Threat vectors
    r = test_endpoint(
        "GET /api/v1/analytics/threat-vectors?limit=10",
        "GET",
        f"{BASE_URL}/api/v1/analytics/threat-vectors?limit=10",
        headers=headers
    )
    if r:
        try:
            data = r.json()["data"]
            print(f"    -&gt; Threat types: {len(data)}")
        except:
            pass
    
    # Geo distribution
    r = test_endpoint(
        "GET /api/v1/analytics/geo-distribution",
        "GET",
        f"{BASE_URL}/api/v1/analytics/geo-distribution",
        headers=headers
    )
    if r:
        try:
            data = r.json()["data"]
            print(f"    -&gt; Countries: {len(data)}")
        except:
            pass
    
    # Traffic analysis
    r = test_endpoint(
        "GET /api/v1/analytics/traffic",
        "GET",
        f"{BASE_URL}/api/v1/analytics/traffic",
        headers=headers
    )
    if r:
        try:
            data = r.json()["data"]
            print(f"    -&gt; Protocols: {len(data)}")
        except:
            pass


def test_v1_alerts(token):
    """Test V1 alert endpoints."""
    print_header("5. V1 Alert Endpoints (Auth Required)")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # List alerts
    r = test_endpoint(
        "GET /api/v1/alerts",
        "GET",
        f"{BASE_URL}/api/v1/alerts",
        headers=headers
    )
    alert_id = None
    if r:
        try:
            data = r.json()
            alerts = data.get("data", [])
            pagination = data.get("pagination", {})
            print(f"    -&gt; Alerts: {len(alerts)} / Total: {pagination.get('total')}")
            if alerts:
                alert_id = alerts[0]["id"]
        except:
            pass
    
    # List alerts with filters
    test_endpoint(
        "GET /api/v1/alerts?severity=high&status=open",
        "GET",
        f"{BASE_URL}/api/v1/alerts?severity=high&status=open",
        headers=headers
    )
    
    # List alerts with pagination
    test_endpoint(
        "GET /api/v1/alerts?page=1&limit=5",
        "GET",
        f"{BASE_URL}/api/v1/alerts?page=1&limit=5",
        headers=headers
    )
    
    # Get single alert (if we have one)
    if alert_id:
        r = test_endpoint(
            f"GET /api/v1/alerts/{alert_id}",
            "GET",
            f"{BASE_URL}/api/v1/alerts/{alert_id}",
            headers=headers
        )
        if r:
            try:
                data = r.json()["data"]
                print(f"    -&gt; Alert ID: {data.get('id')}")
                print(f"    -&gt; Type: {data.get('type')}")
                print(f"    -&gt; Related Logs: {len(data.get('related_logs', []))}")
                print(f"    -&gt; Recommendations: {len(data.get('recommendations', []))}")
            except:
                pass
    
    # Test 404 for non-existent alert
    test_endpoint(
        "GET /api/v1/alerts/99999 (expect 404)",
        "GET",
        f"{BASE_URL}/api/v1/alerts/99999",
        404,
        headers=headers
    )


def test_v1_assets(token):
    """Test V1 asset endpoints."""
    print_header("6. V1 Asset Endpoints (Auth Required)")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # List assets
    r = test_endpoint(
        "GET /api/v1/assets",
        "GET",
        f"{BASE_URL}/api/v1/assets",
        headers=headers
    )
    device_id = None
    if r:
        try:
            data = r.json()
            assets = data.get("data", [])
            pagination = data.get("pagination", {})
            print(f"    -&gt; Assets: {len(assets)} / Total: {pagination.get('total')}")
            if assets:
                device_id = assets[0]["device_id"]
        except:
            pass
    
    # List assets with search
    test_endpoint(
        "GET /api/v1/assets?search=device",
        "GET",
        f"{BASE_URL}/api/v1/assets?search=device",
        headers=headers
    )
    
    # Asset summary
    r = test_endpoint(
        "GET /api/v1/assets/summary",
        "GET",
        f"{BASE_URL}/api/v1/assets/summary",
        headers=headers
    )
    if r:
        try:
            data = r.json()["data"]
            print(f"    -&gt; Total Assets: {data.get('total')}")
            print(f"    -&gt; With Threats: {data.get('with_threats')}")
        except:
            pass
    
    # Get single asset (if we have one)
    if device_id:
        test_endpoint(
            f"GET /api/v1/assets/{device_id}",
            "GET",
            f"{BASE_URL}/api/v1/assets/{device_id}",
            headers=headers
        )
    
    # Test 404 for non-existent asset
    test_endpoint(
        "GET /api/v1/assets/non-existent (expect 404)",
        "GET",
        f"{BASE_URL}/api/v1/assets/non-existent-device-xyz",
        404,
        headers=headers
    )


def test_unauthorized_access():
    """Test that endpoints properly reject unauthorized requests."""
    print_header("7. Authorization Tests (No Token)")
    
    # These should all return 401
    endpoints = [
        "/api/v1/dashboard/summary",
        "/api/v1/analytics/timeline",
        "/api/v1/analytics/threat-vectors",
        "/api/v1/analytics/geo-distribution",
        "/api/v1/alerts",
        "/api/v1/assets",
    ]
    
    for endpoint in endpoints:
        test_endpoint(
            f"GET {endpoint} (expect 401)",
            "GET",
            f"{BASE_URL}{endpoint}",
            401
        )


def test_validation():
    """Test request validation."""
    print_header("8. Validation Tests")
    
    # Need a token for these
    response = requests.post(
        f"{BASE_URL}/auth/login",
        data={"username": "admin", "password": "admin123"},
        timeout=10
    )
    
    if response.status_code != 200:
        print(f"  {RED}Could not get token for validation tests{RESET}")
        return
    
    token = response.json()["data"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Invalid timeline range
    test_endpoint(
        "GET /api/v1/analytics/timeline?range=invalid (expect 422)",
        "GET",
        f"{BASE_URL}/api/v1/analytics/timeline?range=invalid",
        422,
        headers=headers
    )
    
    # Invalid alert severity
    test_endpoint(
        "GET /api/v1/alerts?severity=invalid (expect 422)",
        "GET",
        f"{BASE_URL}/api/v1/alerts?severity=invalid",
        422,
        headers=headers
    )


def main():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  V1 API Endpoint Testing Suite{RESET}")
    print(f"{BOLD}  Target: {BASE_URL}{RESET}")
    print(f"{BOLD}  Time: {datetime.now().isoformat()}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    
    # Test health endpoints first (no auth needed)
    test_health_endpoints()
    
    # Test unauthorized access
    test_unauthorized_access()
    
    # Get auth token
    token = get_auth_token()
    
    if not token:
        print(f"\n{RED}Cannot proceed without authentication token!{RESET}")
        print(f"{YELLOW}Make sure the admin user exists (login: admin / admin123){RESET}")
        return
    
    # Test authenticated endpoints
    test_v1_dashboard(token)
    test_v1_analytics(token)
    test_v1_alerts(token)
    test_v1_assets(token)
    test_validation()
    
    print_header("Testing Complete!")
    print(f"  {GREEN}All endpoint tests executed.{RESET}")
    print(f"  Check the results above for any failures.")
    print()


if __name__ == "__main__":
    main()
