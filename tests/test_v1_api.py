"""Tests for V1 API endpoints — auth removed (handled by Repo 1)."""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
from unittest.mock import patch
import json

from src.api.main import app
from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert

# Disable rate limiting for tests
app.state.limiter.enabled = False

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_db():
    """Initialize database for tests."""
    db_manager.initialize()
    yield
    # Cleanup after tests
    if db_manager.engine:
        db_manager.engine.dispose()


@pytest.fixture(scope="module")
def sample_logs(setup_db):
    """Create sample logs for testing (module-scoped for reuse)."""
    with db_manager.session_scope() as session:
        # Check if logs already exist
        existing = session.query(NormalizedLog).filter(
            NormalizedLog.tenant_id == "test_tenant"
        ).first()
        if existing:
            return True
        
        for i in range(10):
            log = NormalizedLog(
                tenant_id="test_tenant",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                source_ip=f"192.168.1.{i+1}",
                destination_ip="10.0.0.1",
                message=f"Test log message {i}",
                severity=["low", "medium", "high", "critical"][i % 4],
                vendor="TestVendor",
                device_id=f"device-{i % 3}",
                protocol="TCP",
                business_context={"geoip": {"country": "USA", "code": "US"}}
            )
            session.add(log)
        session.commit()
    return True


@pytest.fixture(scope="module")
def sample_alerts(setup_db):
    """Create sample alerts for testing (module-scoped for reuse)."""
    with db_manager.session_scope() as session:
        # Check if alerts already exist
        existing = session.query(Alert).filter(
            Alert.tenant_id == "test_tenant"
        ).first()
        if existing:
            return True
        
        for i in range(5):
            alert = Alert(
                tenant_id="test_tenant",
                alert_type=["brute_force", "port_scan", "suspicious_payload"][i % 3],
                severity=["high", "medium", "critical"][i % 3],
                source_ip=f"192.168.1.{i+1}",
                description=f"Test alert {i}",
                status="open",
                details={"test": True}
            )
            session.add(alert)
        session.commit()
    return True


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_check(self, setup_db):
        """Test basic health check."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert "components" in data

    def test_liveness_check(self, setup_db):
        """Test liveness probe."""
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_metrics_endpoint(self, setup_db):
        """Test Prometheus metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "siem_logs_processed_total" in response.text

    def test_metrics_json(self, setup_db):
        """Test JSON metrics endpoint."""
        response = client.get("/metrics/json")
        assert response.status_code == 200
        data = response.json()
        assert "logs_processed" in data
        assert "uptime_seconds" in data


class TestDashboardEndpoints:
    """Test dashboard summary endpoints."""

    def test_dashboard_summary_no_auth_needed(self):
        """Test dashboard works without auth (auth handled by Repo 1)."""
        response = client.get("/api/v1/dashboard/summary?tenant_id=default")
        assert response.status_code == 200

    def test_dashboard_summary(self, sample_logs, sample_alerts):
        """Test dashboard summary with data."""
        response = client.get("/api/v1/dashboard/summary?tenant_id=test_tenant")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "total_events" in data["data"]
        assert "active_threats" in data["data"]
        assert "risk_score" in data["data"]


class TestAnalyticsEndpoints:
    """Test analytics endpoints."""

    def test_timeline(self, sample_logs):
        """Test timeline endpoint."""
        response = client.get(
            "/api/v1/analytics/timeline?range=24h&bucket=hour&tenant_id=test_tenant"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "series" in data["data"]
        assert data["data"]["range"] == "24h"

    def test_timeline_invalid_range(self):
        """Test timeline with invalid range."""
        response = client.get(
            "/api/v1/analytics/timeline?range=invalid&tenant_id=test_tenant"
        )
        assert response.status_code == 422  # Validation error

    def test_threat_vectors(self, sample_alerts):
        """Test threat vectors endpoint."""
        response = client.get(
            "/api/v1/analytics/threat-vectors?limit=10&tenant_id=test_tenant"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert isinstance(data["data"], list)

    def test_geo_distribution(self, sample_logs):
        """Test geo distribution endpoint."""
        response = client.get(
            "/api/v1/analytics/geo-distribution?tenant_id=test_tenant"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_traffic_analysis(self, sample_logs):
        """Test traffic analysis endpoint."""
        response = client.get(
            "/api/v1/analytics/traffic?tenant_id=test_tenant"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


class TestAlertEndpoints:
    """Test alert endpoints."""

    def test_list_alerts(self, sample_alerts):
        """Test list alerts endpoint."""
        response = client.get("/api/v1/alerts?tenant_id=test_tenant")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "pagination" in data
        assert isinstance(data["data"], list)

    def test_list_alerts_with_filters(self, sample_alerts):
        """Test list alerts with severity filter."""
        response = client.get(
            "/api/v1/alerts?severity=high&status=open&tenant_id=test_tenant"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_list_alerts_pagination(self, sample_alerts):
        """Test alert pagination."""
        response = client.get(
            "/api/v1/alerts?page=1&limit=2&tenant_id=test_tenant"
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) <= 2
        assert "pagination" in data

    def test_get_alert_detail(self, sample_alerts):
        """Test get single alert detail."""
        # First get an alert ID
        list_response = client.get("/api/v1/alerts?tenant_id=test_tenant")
        if list_response.json()["data"]:
            alert_id = list_response.json()["data"][0]["id"]
            
            response = client.get(f"/api/v1/alerts/{alert_id}?tenant_id=test_tenant")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert "recommendations" in data["data"]
            assert "related_logs" in data["data"]

    def test_get_alert_not_found(self):
        """Test get non-existent alert."""
        response = client.get("/api/v1/alerts/99999?tenant_id=test_tenant")
        assert response.status_code == 404


class TestAssetEndpoints:
    """Test asset endpoints."""

    def test_list_assets(self, sample_logs):
        """Test list assets endpoint."""
        response = client.get("/api/v1/assets?tenant_id=test_tenant")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "pagination" in data

    def test_list_assets_with_search(self, sample_logs):
        """Test list assets with search filter."""
        response = client.get(
            "/api/v1/assets?search=device&tenant_id=test_tenant"
        )
        assert response.status_code == 200

    def test_asset_summary(self, sample_logs):
        """Test asset summary endpoint."""
        response = client.get("/api/v1/assets/summary?tenant_id=test_tenant")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "total" in data["data"]

    def test_get_asset_not_found(self):
        """Test get non-existent asset."""
        response = client.get(
            "/api/v1/assets/non-existent-device?tenant_id=test_tenant"
        )
        assert response.status_code == 404
