import pytest
from fastapi.testclient import TestClient
from src.api.main import app
import os

from src.core.database import db_manager

client = TestClient(app)

# Use the same admin key as defined in test environment or mock it
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "changeme-admin-key")

@pytest.fixture(autouse=True)
def setup_env():
    os.environ["ADMIN_API_KEY"] = ADMIN_KEY
    db_manager.initialize()

@pytest.mark.parametrize("endpoint", [
    "/stats",
    "/alerts",
    "/logs",
    "/reports",
    "/analytics/business-insights",
    "/trends",
    "/analytics/top-ips",
    "/analytics/protocols",
    "/config",
    "/api/dashboard-summary"
])
def test_legacy_endpoint_requires_auth(endpoint):
    """Verify that legacy routes now return 401/422/403 when admin key is missing."""
    response = client.get(endpoint)
    # verify_admin_key raises HTTPException(401 or 403) or FastAPI returns 422 if header missing (if required as parameter)
    # Our implementation uses Depends(verify_admin_key) which looks at headers.
    assert response.status_code in [401, 403, 422]

@pytest.mark.parametrize("endpoint", [
    "/stats",
    "/alerts",
    "/logs",
    "/analytics/protocols",
    "/config",
    "/api/dashboard-summary"
])
def test_legacy_endpoint_accepts_correct_key(endpoint):
    """Verify that legacy routes accept the correct X-Admin-Key."""
    # We use a default tenant 'default' for these tests to avoid DB issues
    params = {"tenant_id": "default"}
    response = client.get(endpoint, headers={"X-Admin-Key": ADMIN_KEY}, params=params)
    
    # We expect 200 (access granted). 
    # Even if they return empty data due to mock DB, 200 means auth passed.
    assert response.status_code == 200

def test_config_post_requires_auth():
    """Verify POST /config is protected."""
    response = client.post("/config", json={"brute_force_threshold": 10})
    assert response.status_code in [401, 403, 422]

def test_config_post_accepts_correct_key():
    """Verify POST /config accepts correct key."""
    # Mocking config set to avoid actual file writes during test if possible
    # but here we just check if it gets past the security layer.
    response = client.post(
        "/config", 
        json={"brute_force_threshold": 10}, 
        headers={"X-Admin-Key": ADMIN_KEY}
    )
    # It might return a 200 or 500 if file write fails in test env, 
    # but 200 is expected if all goes well.
    assert response.status_code == 200
