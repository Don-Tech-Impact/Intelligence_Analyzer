#     import json
# import os
# import sys

import requests

# Configuration
BASE_URL = "http://localhost:8000"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "SecurePass123!"

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def test_endpoint(name, method, endpoint, headers=None, data=None, json_data=None, expected_status=200):
    url = f"{BASE_URL}{endpoint}"
    print(f"  {BOLD}{CYAN}Testing {name}{RESET} [{method} {endpoint}]...")

    try:
        response = requests.request(method=method, url=url, headers=headers, data=data, json=json_data, timeout=10)

        status = response.status_code
        if status == expected_status:
            print(f"   {GREEN}[PASS]{RESET} Status: {status}")
            return response
        else:
            print(f"   {RED}[FAIL]{RESET} Status: {status} (Expected: {expected_status})")
            if status >= 400:
                try:
                    print(f"    - Details: {response.json()}")
                except Exception as e:
                    print(f"    - Error: {e}")
                    print(f"    - Body: {response.text[:200]}")
            return None
    except Exception as e:
        print(f"   {RED}[ERROR]{RESET} {str(e)}")
        return None


def run_proxy_tests():
    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  Repo 1 Proxy Endpoint Audit{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")

    # 1. Login to get token
    print(f"\n{BOLD}1. Authentication{RESET}")
    login_data = {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    login_res = test_endpoint("Proxy Login", "POST", "/api/admin/proxy/login", json_data=login_data)

    if not login_res:
        print(f"{RED}Cannot proceed without authentication!{RESET}")
        return

    try:
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"   {GREEN}-> Token obtained successfully{RESET}")
    except Exception as e:
        print(f"   {RED}-> Failed to parse token: {e}{RESET}")
        return

    # 2. Test Admin Proxy Endpoints (Repo 1)
    print(f"\n{BOLD}2. Admin Proxy Endpoints{RESET}")

    # List Tenants
    test_endpoint("List Tenants", "GET", "/api/admin/tenants", headers=headers)

    # List Users
    test_endpoint("List Users", "GET", "/api/admin/users", headers=headers)

    # Get JWT Config
    test_endpoint("JWT Public Config", "GET", "/api/admin/auth/jwt-public-config", headers=headers)

    # Unified Health
    test_endpoint("Unified Health", "GET", "/api/admin/system/health/unified", headers=headers)

    # 3. Test V1 Proxy Endpoints
    print(f"\n{BOLD}3. V1 User Proxy Endpoints{RESET}")

    # Get Primary IP
    test_endpoint("Get Primary IP", "GET", "/api/v1/assets/primary-ip", headers=headers)

    # Get My Devices
    test_endpoint("Get My Devices", "GET", "/api/v1/assets/my-devices", headers=headers)

    # 4. Cleanup / Logout
    print(f"\n{BOLD}4. Session End{RESET}")
    test_endpoint("Proxy Logout", "POST", "/api/admin/logout", headers=headers)

    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  Audit Complete{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")


if __name__ == "__main__":
    run_proxy_tests()
