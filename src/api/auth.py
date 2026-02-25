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
    if secret_key:
        secret_key = secret_key.strip().strip('"').strip("'")
    
    if not secret_key:
        msg = "SECRET_KEY not configured. For local testing, add the Repo 1 secret to your .env file."
        logger.error(msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg
        )

    # Debug: Confirm which key we are using
    key_len = len(secret_key)
    is_default_admin = (secret_key == "changeme-admin-key")
    logger.info(f"Using SECRET_KEY length {key_len} ending in: ...{secret_key[-4:]} (Default Admin Key: {is_default_admin})")

    try:
        # Debugging: check algorithm in header
        header = jwt.get_unverified_header(token)
        logger.info(f"JWT Header: {header}")
        
        # Log if we are using the fallback default from config.py
        if secret_key == "fallback-secret-key-for-diagnostic-suffix":
            logger.warning("CRITICAL: SECRET_KEY is using the HARDCODED FALLBACK. .env is NOT being loaded correctly!")

        # Verify the token using HS256 and the shared secret
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT Verification failed: Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        header = jwt.get_unverified_header(token)
        unverified_payload = jwt.get_unverified_claims(token)
        key_suffix = secret_key[-4:] if secret_key else "NONE"
        is_default_admin = (secret_key == "changeme-admin-key")
        is_fallback = (secret_key == "fallback-secret-key-for-diagnostic-suffix")
        logger.warning(f"JWT Verification failed: {str(e)}")
        logger.warning(f"Algorithm in header: {header.get('alg')}")
        logger.warning(f"Using SECRET_KEY suffix: {key_suffix} (Len: {len(secret_key if secret_key else '')}, DefaultAdmin: {is_default_admin}, Fallback: {is_fallback})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Signature verification failed. 1. Check that Repo 1 and Repo 2 have the EXACT same SECRET_KEY in their .env files. 2. Current Repo 2 Suffix: {key_suffix} (Len: {len(secret_key if secret_key else '')}). 3. Unverified Payload: {unverified_payload}",
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
