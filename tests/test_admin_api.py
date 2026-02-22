"""Tests for the Admin API Router (service-to-service endpoints)."""

import os
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.core.database import db_manager
from src.models.database import Base, Tenant, Alert, NormalizedLog, Report


ADMIN_KEY = os.getenv("ADMIN_API_KEY", "changeme-admin-key")
ADMIN_HEADERS = {"X-Admin-Key": ADMIN_KEY}


@pytest.fixture(scope="module", autouse=True)
def test_db():
    """Initialize an in-memory SQLite database with test data."""
    _orig_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    db_manager.initialize()

    Base.metadata.drop_all(db_manager.engine)
    Base.metadata.create_all(db_manager.engine)

    db = db_manager.get_session()

    # Create test tenants
    db.add(Tenant(tenant_id="acme_corp", name="Acme Corporation"))
    db.add(Tenant(tenant_id="globex", name="Globex Inc", is_active=False))

    # Create some alerts for acme_corp
    for sev in ["critical", "high", "medium", "low"]:
        db.add(Alert(
            tenant_id="acme_corp",
            alert_type="brute_force",
            severity=sev,
            status="open",
            description=f"Test {sev} alert",
            source_ip="10.0.0.1"
        ))

    db.commit()
    yield db
    db.close()
    db_manager.close()
    if db_manager.engine:
        db_manager.engine.dispose()
    if _orig_db_url:
        os.environ["DATABASE_URL"] = _orig_db_url
    elif "DATABASE_URL" in os.environ:
        del os.environ["DATABASE_URL"]


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ===== Auth Tests =====

class TestAdminAuth:
    def test_missing_admin_key_returns_422(self, client):
        resp = client.get("/api/admin/system/overview")
        assert resp.status_code == 422

    def test_wrong_admin_key_returns_403(self, client):
        resp = client.get(
            "/api/admin/system/overview",
            headers={"X-Admin-Key": "wrong-key"}
        )
        assert resp.status_code == 403
        assert "Invalid admin API key" in resp.json()["detail"]

    def test_correct_admin_key_passes(self, client):
        resp = client.get("/api/admin/system/overview", headers=ADMIN_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"


# ===== System Overview Tests =====

class TestSystemOverview:
    def test_returns_expected_shape(self, client):
        resp = client.get("/api/admin/system/overview", headers=ADMIN_HEADERS)
        assert resp.status_code == 200

        body = resp.json()
        assert body["status"] == "success"
        data = body["data"]

        # Top-level keys
        assert "tenants" in data
        assert "logs" in data
        assert "alerts" in data
        assert "reports" in data
        assert "dead_letters" in data
        assert "estimated_storage_bytes" in data
        assert "top_tenants_by_volume" in data

        # Nested structure
        assert "total" in data["tenants"]
        assert "active" in data["tenants"]
        assert "inactive" in data["tenants"]
        assert "total" in data["logs"]
        assert "last_24h" in data["logs"]
        assert "by_severity" in data["alerts"]

    def test_tenant_counts_are_correct(self, client):
        resp = client.get("/api/admin/system/overview", headers=ADMIN_HEADERS)
        data = resp.json()["data"]

        assert data["tenants"]["total"] == 2
        assert data["tenants"]["active"] == 1
        assert data["tenants"]["inactive"] == 1

    def test_alert_counts_are_correct(self, client):
        resp = client.get("/api/admin/system/overview", headers=ADMIN_HEADERS)
        data = resp.json()["data"]

        assert data["alerts"]["total"] == 4  # 4 alerts created in fixture
        assert "critical" in data["alerts"]["by_severity"]
        assert data["alerts"]["by_severity"]["critical"] == 1

    def test_values_are_non_negative(self, client):
        resp = client.get("/api/admin/system/overview", headers=ADMIN_HEADERS)
        data = resp.json()["data"]

        assert data["tenants"]["total"] >= 0
        assert data["logs"]["total"] >= 0
        assert data["alerts"]["total"] >= 0
        assert data["reports"] >= 0
        assert data["dead_letters"] >= 0


# ===== Tenant Usage Tests =====

class TestTenantUsage:
    def test_nonexistent_tenant_returns_404(self, client):
        resp = client.get(
            "/api/admin/tenants/does_not_exist/usage",
            headers=ADMIN_HEADERS
        )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_existing_tenant_returns_usage(self, client):
        resp = client.get(
            "/api/admin/tenants/acme_corp/usage",
            headers=ADMIN_HEADERS
        )
        assert resp.status_code == 200

        data = resp.json()["data"]
        assert data["tenant_id"] == "acme_corp"
        assert data["tenant_name"] == "Acme Corporation"
        assert data["is_active"] is True
        assert "logs" in data
        assert "alerts" in data
        assert "reports" in data

    def test_tenant_alert_counts(self, client):
        resp = client.get(
            "/api/admin/tenants/acme_corp/usage",
            headers=ADMIN_HEADERS
        )
        data = resp.json()["data"]

        assert data["alerts"]["total"] == 4
        assert data["alerts"]["active"] == 4  # all are "open"
        assert data["alerts"]["by_severity"]["critical"] == 1

    def test_inactive_tenant_returns_usage(self, client):
        resp = client.get(
            "/api/admin/tenants/globex/usage",
            headers=ADMIN_HEADERS
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["is_active"] is False

    def test_requires_admin_key(self, client):
        resp = client.get("/api/admin/tenants/acme_corp/usage")
        assert resp.status_code == 422

    def test_rejects_wrong_key(self, client):
        resp = client.get(
            "/api/admin/tenants/acme_corp/usage",
            headers={"X-Admin-Key": "bad-key"}
        )
        assert resp.status_code == 403
