"""Tests for Tenant Isolation and Data Privacy."""

import os
import pytest
from fastapi.testclient import TestClient
from datetime import datetime

from src.api.main import app
from src.core.database import db_manager
from src.models.database import Base, Tenant, Alert, NormalizedLog
from src.api.auth import verify_jwt

# ---------------------------------------------------------------------------
# Mock JWT — V1 router requires verify_jwt on every endpoint.
# Override it so tests don't need a live Repo 1 token.
# ---------------------------------------------------------------------------
MOCK_JWT_PAYLOAD = {
    "sub": "test-admin-uuid",
    "email": "test@example.com",
    "role": "superadmin",
    "iss": "repo1-admin-api",
}
app.dependency_overrides[verify_jwt] = lambda: MOCK_JWT_PAYLOAD

client = TestClient(app)

TENANT_A = "company_alpha"
TENANT_B = "company_beta"

@pytest.fixture(scope="module", autouse=True)
def test_db():
    """Setup a multi-tenant test database."""
    _orig_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    db_manager.initialize()

    Base.metadata.drop_all(db_manager.engine)
    Base.metadata.create_all(db_manager.engine)

    db = db_manager.get_session()

    # Create two tenants
    db.add(Tenant(tenant_id=TENANT_A, name="Company Alpha"))
    db.add(Tenant(tenant_id=TENANT_B, name="Company Beta"))

    # Add logs for Tenant A
    db.add(NormalizedLog(
        tenant_id=TENANT_A,
        log_type="access",
        source_ip="1.1.1.1",
        message="Alpha sensitive log",
        timestamp=datetime.utcnow()
    ))

    # Add logs for Tenant B
    db.add(NormalizedLog(
        tenant_id=TENANT_B,
        log_type="access",
        source_ip="2.2.2.2",
        message="Beta sensitive log",
        timestamp=datetime.utcnow()
    ))

    # Add alert for Tenant A
    db.add(Alert(
        tenant_id=TENANT_A,
        alert_type="malware",
        severity="critical",
        status="open",
        description="Alpha critical alert"
    ))

    db.commit()
    yield db
    db.close()
    db_manager.close()
    if _orig_db_url:
        os.environ["DATABASE_URL"] = _orig_db_url


class TestTenantIsolation:
    """Verify that Tenant A cannot see Tenant B's data."""

    def test_logs_isolation(self):
        """TENANT_A logs request should not return TENANT_B logs."""
        resp = client.get(f"/api/v1/logs?tenant_id={TENANT_A}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        
        # Should only have 1 log (Alpha)
        assert len(data) == 1
        assert data[0]["tenant_id"] == TENANT_A
        assert "Alpha" in data[0]["message"]
        
        # Verify negative: no Beta log
        assert all("Beta" not in log["message"] for log in data)

    def test_alerts_isolation(self):
        """TENANT_B alerts request should be empty if no alerts exist for B."""
        resp = client.get(f"/api/v1/alerts?tenant_id={TENANT_B}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        
        # Should be empty (no alerts added for B in fixture)
        assert len(data) == 0

    def test_summary_isolation(self):
        """Summary counts should be isolated per tenant."""
        resp_a = client.get(f"/api/v1/dashboard/summary?tenant_id={TENANT_A}")
        data_a = resp_a.json()["data"]
        
        resp_b = client.get(f"/api/v1/dashboard/summary?tenant_id={TENANT_B}")
        data_b = resp_b.json()["data"]

        # A has 1 alert, B has 0
        assert data_a["active_threats"]["count"] == 1
        assert data_b["active_threats"]["count"] == 0

        # A has 1 event, B has 1 (but different events)
        assert data_a["total_events"]["count"] == 1
        assert data_b["total_events"]["count"] == 1

    def test_alert_detail_isolation(self):
        """Tenant B should not be able to view details of Tenant A's alert."""
        # Get Alpha's alert ID
        resp = client.get(f"/api/v1/alerts?tenant_id={TENANT_A}")
        alert_id = resp.json()["data"][0]["id"]

        # Try to access as Beta
        resp_forbidden = client.get(f"/api/v1/alerts/{alert_id}?tenant_id={TENANT_B}")
        assert resp_forbidden.status_code == 404
        assert "not found" in resp_forbidden.json()["detail"].lower()
