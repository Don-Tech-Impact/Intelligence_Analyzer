from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Optional, Dict, Any
import os
import logging

from src.core.config import config

logger = logging.getLogger(__name__)

# This will be pointing to our login endpoint in the future
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/dashboard/login", auto_error=False)

def get_public_key() -> Optional[str]:
    """Get the RS256 public key from config/env."""
    key = config.jwt_public_key
    if not key:
        return None
    
    # Ensure it has the proper PEM headers if missing
    if "BEGIN PUBLIC KEY" not in key:
        key = f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"
    
    return key

async def verify_jwt(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Verify a JWT using the RS256 public key.
    
    If no public key is configured, it will log a warning and block access 
    (fail-secure) unless we are in developmental mode.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    public_key = get_public_key() # We keep this for backward compatibility if needed, but primary is now HS256
    secret_key = config.secret_key
    
    if not secret_key:
        msg = "SECRET_KEY not configured. For local testing, add the Repo 1 secret to your .env file."
        logger.error(msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg
        )

    try:
        # Verify the token using HS256 and the shared secret
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        return payload
    except JWTError as e:
        logger.warning(f"JWT Verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(payload: Dict[str, Any] = Depends(verify_jwt)) -> Dict[str, Any]:
    """Extract user info from verified payload."""
    return payload

async def verify_superadmin(payload: Dict[str, Any] = Depends(verify_jwt)):
    """Check if the user has superadmin privileges."""
    role = payload.get("role", "").lower()
    is_admin = payload.get("is_admin", False)
    username = payload.get("username", "").lower()
    
    # Repo 1 often nests claims in 'admin' object
    admin_obj = payload.get("admin", {})
    if isinstance(admin_obj, dict):
        role = role or admin_obj.get("role", "").lower()
        is_admin = is_admin or admin_obj.get("is_admin", False)
        username = username or admin_obj.get("username", "").lower()

    email = payload.get("email", "").lower()
    
    is_super = (
        role == "superadmin" or 
        is_admin is True or 
        username == "superadmin" or 
        "admin@" in email
    )

    if not is_super:
        logger.warning(f"Access Denied for payload: {payload}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Superadmin access required."
        )
    return payload
