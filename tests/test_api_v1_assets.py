import pytest
import respx
import httpx
from fastapi.testclient import TestClient
from src.api.main import app
from src.api.v1_router import verify_jwt, get_tenant_id
from src.core.database import db_manager
from src.models.database import ManagedDevice, Base
import os

# Mock JWT for V1 Router
MOCK_JWT = {"sub": "test-uuid", "tenant_id": "test_tenant", "role": "admin"}
app.dependency_overrides[verify_jwt] = lambda: MOCK_JWT
app.dependency_overrides[get_tenant_id] = lambda: "test_tenant"

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def test_db():
    db_manager.initialize() 
    Base.metadata.create_all(db_manager.engine)
    yield
    db_manager.close()

@respx.mock
def test_register_managed_device_success():
    """Test registering a managed device and syncing with Repo 1."""
    payload = {"name": "Test Server", "ip_address": "10.0.0.50", "category": "server"}
    
    # Mock Repo 1 Allowlist Sync using regular expression for matching
    respx.post(url__regex=r".*/ips$").mock(
        return_value=httpx.Response(200, json={"status": "success"})
    )
    
    response = client.post("/api/v1/assets/managed", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["data"]["name"] == "Test Server"
    assert data["data"]["ip_address"] == "10.0.0.50"
    
    # Verify database entry
    with db_manager.session_scope() as session:
        device = session.query(ManagedDevice).filter_by(ip_address="10.0.0.50").first()
        assert device is not None
        assert device.tenant_id == "test_tenant"

@respx.mock
def test_register_managed_device_missing_fields():
    """Test validation errors."""
    payload = {"name": "Incomplete"} # Missing IP
    response = client.post("/api/v1/assets/managed", json=payload)
    # This should be 400 since we fixed the HTTPException handling
    assert response.status_code == 400
    assert "required" in response.json()["detail"].lower()

@respx.mock
def test_register_managed_device_sync_fails_gracefully():
    """Test that if Repo 1 sync fails, the local registration still succeeds."""
    payload = {"name": "Test Asset 2", "ip_address": "10.0.0.60"}
    
    # Mock Repo 1 error
    respx.post(url__regex=r".*/ips$").mock(
        return_value=httpx.Response(500, text="Internal Error")
    )
    
    response = client.post("/api/v1/assets/managed", json=payload)
    
    # The code handles this via try-except and print, so it should still return 200
    assert response.status_code == 200
    assert response.json()["data"]["ip_address"] == "10.0.0.60"
