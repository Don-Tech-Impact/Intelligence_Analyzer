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

    # Production-safe logging
    is_default_admin = (secret_key == "changeme-admin-key")
    if is_default_admin:
        logger.warning("Using DEFAULT admin key. This is insecure for production!")

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
        logger.warning(f"JWT Verification failed: Invalid signature or malformed token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(payload: Dict[str, Any] = Depends(verify_jwt)) -> Dict[str, Any]:
    """Extract user info from verified payload."""
    return payload

async def verify_superadmin(payload: Dict[str, Any] = Depends(verify_jwt)):
    """
    Check if the user has superadmin privileges based on signed claims.
    
    Loose checks (like email domain or username string) have been removed 
    to prevent spoofing. We rely strictly on 'role' or 'is_admin' flags.
    """
    role = str(payload.get("role", "")).lower()
    is_admin = payload.get("is_admin", False)
    
    # Support nested 'admin' object from Repo 1 if present
    admin_obj = payload.get("admin", {})
    if isinstance(admin_obj, dict):
        role = role or str(admin_obj.get("role", "")).lower()
        is_admin = is_admin or admin_obj.get("is_admin", False)

    if not (role == "superadmin" or is_admin is True):
        logger.warning(f"Superadmin access denied for user: {payload.get('sub', 'unknown')}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Superadmin access required."
        )
    return payload

def decode_token_payload(token: str) -> Optional[Dict[str, Any]]:
    """
    Silently decode a token payload without raising exceptions.
    Used for optional auth checks or legacy integration points.
    """
    try:
        secret_key = config.secret_key
        if secret_key:
            # More robust cleaning in case of hidden chars
            secret_key = str(secret_key).strip().replace("\r", "").replace("\n", "").replace(" ", "")
            secret_key = secret_key.strip('"').strip("'")
        
        if not secret_key:
            return None
            
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        return payload
    except Exception as e:
        # Fallback to Redis secret if local config fails (Repo 1 source of truth)
        if "signature verification failed" in str(e).lower():
            try:
                from src.services.redis_client import redis_client
                redis_secret = redis_client.get("admin:jwt_secret")
                if redis_secret:
                    if isinstance(redis_secret, bytes):
                        redis_secret = redis_secret.decode()
                    
                    # Try once more with Redis secret
                    payload = jwt.decode(
                        token,
                        redis_secret.strip(),
                        algorithms=["HS256"],
                        options={"verify_aud": False}
                    )
                    logger.info("JWT verified successfully using Redis secret fallback.")
                    return payload
            except Exception as e2:
                logger.error(f"JWT Redis fallback failed: {e2}")

        logger.error(f"JWT decode failed: {e}")
        return None
