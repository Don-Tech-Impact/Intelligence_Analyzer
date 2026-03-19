import pytest
import respx
import httpx
from fastapi.testclient import TestClient
from src.api.main import app
import os

# Set necessary environment variables for testing
os.environ["REPO1_BASE_URL"] = "http://repo1-test"
os.environ["ADMIN_KEY"] = "test-admin-key"

client = TestClient(app)

@respx.mock
@pytest.mark.asyncio
async def test_proxy_login_admin_success():
    """Test that admin login (email) routes correctly and normalizes access_token."""
    payload = {"email": "admin@test.com", "password": "pass"}
    
    # Mock Repo 1 Admin Login
    respx.post("http://repo1-test/admin/login").mock(
        return_value=httpx.Response(200, json={"token": "mock-jwt-admin"})
    )
    
    response = client.post("/api/admin/proxy/login", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "mock-jwt-admin"
    assert len(respx.calls) == 1
    assert respx.calls[0].request.url == "http://repo1-test/admin/login"

@respx.mock
@pytest.mark.asyncio
async def test_proxy_login_tenant_success():
    """Test that tenant login (username) routes correctly."""
    payload = {"username": "tenant_user", "password": "pass"}
    
    # Mock Repo 1 Tenant Login
    respx.post("http://repo1-test/tenant/login").mock(
        return_value=httpx.Response(200, json={"access_token": "mock-jwt-tenant"})
    )
    
    response = client.post("/api/admin/proxy/login", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "mock-jwt-tenant"
    assert respx.calls[0].request.url == "http://repo1-test/tenant/login"

@respx.mock
@pytest.mark.asyncio
async def test_proxy_login_auth_failure():
    """Test that 401/403 from Repo 1 returns a standardized 401 error."""
    payload = {"email": "bad@test.com", "password": "pass"}
    
    # Mock Repo 1 403
    respx.post("http://repo1-test/admin/login").mock(
        return_value=httpx.Response(403, json={"detail": "Private error message"})
    )
    
    response = client.post("/api/admin/proxy/login", json=payload)
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials or unauthorized access."

@respx.mock
@pytest.mark.asyncio
async def test_proxy_login_backend_500():
    """Test that 500 errors from backend are relayed with a generic message."""
    payload = {"email": "bug@test.com", "password": "pass"}
    
    respx.post("http://repo1-test/admin/login").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )
    
    response = client.post("/api/admin/proxy/login", json=payload)
    
    assert response.status_code == 500
    assert "Authentication system encountered an issue" in response.json()["detail"]

@respx.mock
@pytest.mark.asyncio
async def test_proxy_login_timeout():
    """Test that if Repo 1 is latent, Repo 2 handles it (timeout in code is 10s)."""
    payload = {"email": "slow@test.com", "password": "pass"}
    
    # Mock a timeout or a very slow response
    respx.post("http://repo1-test/admin/login").mock(side_effect=httpx.TimeoutException("Too slow"))
    
    response = client.post("/api/admin/proxy/login", json=payload)
    
    # The code's 'except' block raises 401: Authentication currently unavailable.
    assert response.status_code == 401
    assert "unavailable" in response.json()["detail"].lower()

@respx.mock
@pytest.mark.asyncio
async def test_proxy_logout_admin():
    """Test logout routing for admin (using a mock JWT)."""
    # We'll use a mocked JWT decode if needed, or rely on the logic in src/api/admin_router.py:514
    
    import jwt # For creating a test token
    token_payload = {"user_type": "admin", "sub": "admin_user"}
    token = jwt.encode(token_payload, "test-secret", algorithm="HS256")
    
    headers = {"Authorization": f"Bearer {token}", "X-Admin-Key": "test-admin-key"}
    
    respx.post("http://repo1-test/admin/logout").mock(
        return_value=httpx.Response(200, json={"status": "logged out"})
    )
    
    # We need to ensure config.secret_key matches for the decode if it was checked,
    # but the code uses getattr(config, "secret_key", ""). Let's just mock Repo 1.
    
    response = client.post("/api/admin/logout", headers=headers)
    
    assert response.status_code == 200
    assert respx.calls[0].request.url == "http://repo1-test/admin/logout"

@respx.mock
@pytest.mark.asyncio
async def test_proxy_logout_tenant():
    """Test logout routing for tenant_user."""
    import jwt
    token_payload = {"user_type": "tenant_user", "sub": "user1"}
    token = jwt.encode(token_payload, "test-secret", algorithm="HS256")
    
    headers = {"Authorization": f"Bearer {token}", "X-Admin-Key": "test-admin-key"}
    
    respx.post("http://repo1-test/tenant/logout").mock(
        return_value=httpx.Response(200, json={"status": "logged out"})
    )
    
    response = client.post("/api/admin/logout", headers=headers)
    
    assert response.status_code == 200
    assert respx.calls[0].request.url == "http://repo1-test/tenant/logout"
