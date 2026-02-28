import pytest
from fastapi import HTTPException
from src.api.auth import verify_superadmin

@pytest.mark.asyncio
async def test_verify_superadmin_valid_role():
    """Verify that a simple 'superadmin' role claim works."""
    payload = {"sub": "user1", "role": "superadmin"}
    result = await verify_superadmin(payload)
    assert result == payload

@pytest.mark.asyncio
async def test_verify_superadmin_valid_is_admin():
    """Verify that an 'is_admin' flag works."""
    payload = {"sub": "user2", "is_admin": True}
    result = await verify_superadmin(payload)
    assert result == payload

@pytest.mark.asyncio
async def test_verify_superadmin_nested_claims():
    """Verify that Repo 1 style nested claims work."""
    payload = {
        "sub": "user3",
        "admin": {
            "role": "superadmin",
            "is_admin": True
        }
    }
    result = await verify_superadmin(payload)
    assert result == payload

@pytest.mark.asyncio
async def test_verify_superadmin_fails_on_spoofed_email():
    """
    CRITICAL: Verify that the legacy email-based check ('admin@') 
    no longer grants superadmin access.
    """
    payload = {
        "sub": "attacker",
        "email": "admin@malicious-tenant.com",
        "role": "user"
    }
    with pytest.raises(HTTPException) as exc:
        await verify_superadmin(payload)
    assert exc.value.status_code == 403
    assert "Insufficient permissions" in exc.value.detail

@pytest.mark.asyncio
async def test_verify_superadmin_fails_on_spoofed_username():
    """
    Verify that just having the 'superadmin' username string 
    is not enough without the signed role claim.
    """
    payload = {
        "sub": "attacker",
        "username": "superadmin",
        "role": "user"
    }
    with pytest.raises(HTTPException) as exc:
        await verify_superadmin(payload)
    assert exc.value.status_code == 403

@pytest.mark.asyncio
async def test_verify_superadmin_fails_on_regular_user():
    """Basic check for regular user rejection."""
    payload = {"sub": "user4", "role": "user"}
    with pytest.raises(HTTPException) as exc:
        await verify_superadmin(payload)
    assert exc.value.status_code == 403
