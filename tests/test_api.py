import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.core.database import db_manager
from src.models.database import Tenant, Alert

import os
from src.models.database import Base

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module", autouse=True)
def test_db():
    # Use in-memory database for tests
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    db_manager.initialize()
    
    # Ensure a clean slate
    Base.metadata.drop_all(db_manager.engine)
    Base.metadata.create_all(db_manager.engine)
    
    db = db_manager.get_session()
    
    # Create test tenant
    tenant = Tenant(tenant_id="test_tenant", name="Test Tenant")
    db.add(tenant)
    
    # Create a dummy alert
    alert = Alert(
        tenant_id="test_tenant",
        alert_type="Malware Detected",
        severity="critical",
        status="open",
        description="Test Malware Alert",
        source_ip="1.2.3.4"
    )
    db.add(alert)
    
    db.commit()
    yield db
    db.close()
    
    # Cleanup
    db_manager.close()
    if db_manager.engine:
        db_manager.engine.dispose()

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    # Updated to match new health endpoint format
    assert response.json()["status"] in ["healthy", "degraded"]
    assert "components" in response.json()

def test_stats_endpoint(client):
    """Test stats endpoint works without auth."""
    response = client.get("/stats?tenant_id=test_tenant")
    assert response.status_code == 200
    data = response.json()["data"]
    assert "total_logs" in data

def test_dashboard_summary(client):
    response = client.get("/api/dashboard-summary?tenant_id=test_tenant")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["tenant_id"] == "test_tenant"
    assert "stats" in data
    assert "recent_alerts" in data

def test_update_alert_status(client, test_db):
    # Get the alert ID
    alert = test_db.query(Alert).filter(Alert.tenant_id == "test_tenant").first()
    alert_id = alert.id
    
    response = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "acknowledged", "analyst_comment": "Checking this now"}
    )
    assert response.status_code == 200
    assert response.json()["new_status"] == "acknowledged"
    
    # Verify in DB
    test_db.refresh(alert)
    assert alert.status == "acknowledged"
    assert "Analyst: Checking this now" in alert.description
