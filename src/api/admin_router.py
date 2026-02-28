"""Admin API Router for service-to-service communication with Repo1.

Exposes per-tenant usage statistics, system overview endpoints, and
full proxy coverage for all Repo 1 admin endpoints.

Protected by X-Admin-Key header (shared secret between Repo1 and Repo2)
OR a valid Superadmin Bearer JWT.
"""

import os
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Header, Request, Response
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from src.core.database import db_manager
from src.core.config import config
from src.models.database import NormalizedLog, Alert, Tenant, Report, DeadLetter
import httpx
from src.api.auth import verify_superadmin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["Admin (Service-to-Service)"])


# ---------- Auth ----------

def _get_admin_key() -> str:
    """Get the admin API key from environment."""
    key = os.getenv("ADMIN_KEY") or os.getenv("ADMIN_API_KEY")
    if not key:
        # In production contexts, this should fail. We log a critical warning.
        logger.warning("CRITICAL: No ADMIN_KEY configured. Falling back to default for development ONLY.")
        return "changeme-admin-key"
    return key


def _get_repo1_base() -> str:
    """Return the base URL of Repo 1."""
    return (
        os.getenv("REPO1_URL")
        or os.getenv("REPO1_BASE_URL")
        or "http://host.docker.internal:8080"
    ).rstrip("/")


def verify_admin_key(x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")) -> str:
    """Validate X-Admin-Key header matches the configured secret."""
    if not x_admin_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Admin-Key header",
            headers={"WWW-Authenticate": "X-Admin-Key"},
        )
    expected = _get_admin_key()
    if x_admin_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Admin-Key",
        )
    return x_admin_key


def verify_admin_or_superadmin(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    request: Request = None,
):
    """Allow either the service API key or a verified Superadmin Bearer JWT."""
    # --- Option A: X-Admin-Key ---
    if x_admin_key and x_admin_key == _get_admin_key():
        return {"sub": "service-account", "role": "superadmin"}

    # --- Option B: Bearer JWT ---
    if request is not None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            try:
                from src.api.auth import decode_token_payload
                payload = decode_token_payload(token)
                if payload:
                    role = str(payload.get("role", "")).lower()
                    is_admin = payload.get("is_admin", False)
                    
                    # Handle nested Repo 1 admin object
                    admin_obj = payload.get("admin", {})
                    if isinstance(admin_obj, dict):
                        role = role or str(admin_obj.get("role", "")).lower()
                        is_admin = is_admin or admin_obj.get("is_admin", False)

                    if role in ("superadmin", "admin") or is_admin:
                        return payload
            except Exception as e:
                logger.error(f"Auth Trace: Error during JWT verification: {e}")
        else:
            logger.warning(f"Auth Trace: Authorization header does not start with Bearer: {auth_header[:20]}...")
    else:
        logger.warning("Auth Trace: Request object is None")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication. Provide X-Admin-Key or a valid Bearer JWT."
    )


# ---------- Shared Repo 1 HTTP helper ----------

async def _repo1_request(
    method: str,
    path: str,
    body: Optional[dict] = None,
    params: Optional[dict] = None,
    forward_status: bool = False,
) -> dict:
    """Send an authenticated request to Repo 1's admin API.

    Args:
        method:         HTTP verb (GET, POST, PUT, DELETE).
        path:           Path on Repo 1, e.g. "/admin/tenants".
        body:           JSON body for POST/PUT requests.
        params:         Query parameters.
        forward_status: If True, return (status_code, data) tuple.

    Returns:
        Parsed JSON response from Repo 1, or raises HTTPException on error.
    """
    base = _get_repo1_base()
    url = f"{base}{path}"
    headers = {
        "X-Admin-Key": _get_admin_key(),
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=body,
                params=params,
            )
            try:
                data = response.json()
            except Exception:
                data = {"detail": response.text}

            if forward_status:
                return response.status_code, data

            # Propagate 4xx errors from Repo 1 as-is
            if response.status_code >= 400:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=data.get("detail", str(data)),
                )
            return data

        except HTTPException:
            raise
        except Exception as exc:
            logger.error(f"Repo 1 request {method} {url} failed: {exc}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Identity server unreachable: {exc}",
            )


# ---------- Dependencies ----------

def get_db():
    with db_manager.session_scope() as session:
        yield session


# ==========================================================================
# Local analytics endpoints (read from Repo 2's own DB)
# ==========================================================================

@router.get("/tenants/{tenant_id}/usage", dependencies=[Depends(verify_admin_or_superadmin)])
def get_tenant_usage(
    tenant_id: str,
    db: Session = Depends(get_db)
):
    """
    Get per-tenant usage statistics.

    Called by Repo1's admin dashboard to display analytics
    for a specific tenant.

    Returns:
        - Total log count (all time + last 24h + last 7d)
        - Total alert count by severity
        - Report count
        - Dead letter count
        - Estimated storage (bytes)
    """
    # --- Verify tenant exists ---
    tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found"
        )

    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # --- Log counts ---
    total_logs = db.query(func.count(NormalizedLog.id)).filter(
        NormalizedLog.tenant_id == tenant_id
    ).scalar() or 0

    logs_24h = db.query(func.count(NormalizedLog.id)).filter(
        NormalizedLog.tenant_id == tenant_id,
        NormalizedLog.timestamp >= last_24h
    ).scalar() or 0

    logs_7d = db.query(func.count(NormalizedLog.id)).filter(
        NormalizedLog.tenant_id == tenant_id,
        NormalizedLog.timestamp >= last_7d
    ).scalar() or 0

    # --- Alert counts by severity ---
    alert_rows = db.query(
        Alert.severity,
        func.count(Alert.id)
    ).filter(
        Alert.tenant_id == tenant_id
    ).group_by(Alert.severity).all()

    alerts_by_severity = {row[0]: row[1] for row in alert_rows}
    total_alerts = sum(alerts_by_severity.values())

    # Active (non-resolved) alerts
    active_alerts = db.query(func.count(Alert.id)).filter(
        Alert.tenant_id == tenant_id,
        Alert.status != "resolved"
    ).scalar() or 0

    # --- Reports ---
    report_count = db.query(func.count(Report.id)).filter(
        Report.tenant_id == tenant_id
    ).scalar() or 0

    # --- Dead letters ---
    dead_count = db.query(func.count(DeadLetter.id)).filter(
        DeadLetter.tenant_id == tenant_id
    ).scalar() or 0

    # --- Estimated storage (rough: avg 500 bytes per log row) ---
    estimated_storage_bytes = total_logs * 500

    return {
        "status": "success",
        "data": {
            "tenant_id": tenant_id,
            "tenant_name": tenant.name,
            "is_active": tenant.is_active,
            "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
            "logs": {
                "total": total_logs,
                "last_24h": logs_24h,
                "last_7d": logs_7d
            },
            "alerts": {
                "total": total_alerts,
                "active": active_alerts,
                "by_severity": alerts_by_severity
            },
            "reports": report_count,
            "dead_letters": dead_count,
            "estimated_storage_bytes": estimated_storage_bytes
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/system/overview", dependencies=[Depends(verify_admin_or_superadmin)])
def get_system_overview(
    db: Session = Depends(get_db)
):
    """
    Get system-wide statistics across all tenants.

    Called by Repo1's admin dashboard to display a global overview.

    Returns:
        - Total tenants (active / inactive)
        - Total logs, alerts, reports
        - Per-tenant breakdown (top 20 by log volume)
        - System health indicators
    """
    # --- Tenant counts ---
    total_tenants = db.query(func.count(Tenant.id)).scalar() or 0
    active_tenants = db.query(func.count(Tenant.id)).filter(
        Tenant.is_active == True  # noqa: E712
    ).scalar() or 0

    # --- Global counts ---
    total_logs = db.query(func.count(NormalizedLog.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_reports = db.query(func.count(Report.id)).scalar() or 0
    total_dead = db.query(func.count(DeadLetter.id)).scalar() or 0

    # --- Last 24h activity ---
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    logs_24h = db.query(func.count(NormalizedLog.id)).filter(
        NormalizedLog.timestamp >= last_24h
    ).scalar() or 0

    alerts_24h = db.query(func.count(Alert.id)).filter(
        Alert.created_at >= last_24h
    ).scalar() or 0

    # --- Alert severity breakdown (global) ---
    severity_rows = db.query(
        Alert.severity,
        func.count(Alert.id)
    ).group_by(Alert.severity).all()
    alerts_by_severity = {row[0]: row[1] for row in severity_rows}

    # --- Top tenants by log volume (top 20) ---
    tenant_volumes = db.query(
        NormalizedLog.tenant_id,
        func.count(NormalizedLog.id).label("log_count")
    ).group_by(
        NormalizedLog.tenant_id
    ).order_by(
        func.count(NormalizedLog.id).desc()
    ).limit(20).all()

    top_tenants = [
        {"tenant_id": row[0], "log_count": row[1]}
        for row in tenant_volumes
    ]

    return {
        "status": "success",
        "data": {
            "tenants": {
                "total": total_tenants,
                "active": active_tenants,
                "inactive": total_tenants - active_tenants
            },
            "logs": {
                "total": total_logs,
                "last_24h": logs_24h
            },
            "alerts": {
                "total": total_alerts,
                "last_24h": alerts_24h,
                "by_severity": alerts_by_severity
            },
            "reports": total_reports,
            "dead_letters": total_dead,
            "estimated_storage_bytes": total_logs * 500,
            "top_tenants_by_volume": top_tenants
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# ==========================================================================
# Webhook receiver — Repo 1 → Repo 2
# ==========================================================================

@router.post("/tenants/sync", dependencies=[Depends(verify_admin_key)])
async def sync_tenant(payload: dict, db: Session = Depends(get_db)):
    """
    Webhook endpoint for Repo 1 to synchronize tenant data.

    Repo 1 POSTs here after every tenant.created / tenant.updated /
    tenant.deleted event.  The endpoint is idempotent — it is safe to
    receive the same event more than once.

    Expected payload:
        {
            "event": "tenant.created" | "tenant.updated" | "tenant.deleted",
            "tenant": {"tenant_id": str, "name": str, "status": str},
            "timestamp": "<ISO 8601>"
        }
    """
    event = payload.get("event")
    tenant_data = payload.get("tenant", {})
    tenant_id = tenant_data.get("tenant_id")

    if not event or not tenant_id:
        raise HTTPException(status_code=400, detail="Invalid webhook payload: missing 'event' or 'tenant.tenant_id'")

    logger.info(f"Received sync event '{event}' for tenant '{tenant_id}'")

    # Look up existing local tenant record
    existing = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()

    if event == "tenant.deleted":
        if existing:
            existing.is_active = False
            db.commit()
            logger.info(f"Tenant '{tenant_id}' deactivated via webhook")
            return {"status": "success", "message": f"Tenant {tenant_id} deactivated"}
        # Idempotent: not found is fine for a delete event
        return {"status": "ok", "message": "Tenant not found — nothing to delete"}

    # tenant.created or tenant.updated — upsert
    is_active = tenant_data.get("status") == "active"
    if not existing:
        existing = Tenant(
            tenant_id=tenant_id,
            name=tenant_data.get("name", tenant_id),
            is_active=is_active,
        )
        db.add(existing)
        logger.info(f"Created local tenant record for '{tenant_id}'")
    else:
        existing.name = tenant_data.get("name", existing.name)
        existing.is_active = is_active
        logger.info(f"Updated local tenant record for '{tenant_id}'")

    db.commit()
    action = event.split(".", 1)[1] if "." in event else event
    return {"status": "success", "message": f"Tenant {tenant_id} {action}"}


# ==========================================================================
# Auth proxy  (Repo 1 auth endpoints — no admin key required on login)
# ==========================================================================

@router.post("/proxy/login")
async def proxy_login(payload: dict, response: Response):
    """
    Proxy login request to Repo 1 to bypass browser CORS issues.
    Relays the status code and JSON body from Repo 1.
    """
    repo1_base = _get_repo1_base()
    
    # Smart Routing: Check if this is an Admin (email) or Tenant (username) login
    if "username" in payload and "email" not in payload:
        url = f"{repo1_base}/tenant/login"
        logger.info(f"Routing to Tenant Login: {url}")
    else:
        url = f"{repo1_base}/admin/login"
        logger.info(f"Routing to Admin Login: {url}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r1_res = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            
            # Relay the status code
            response.status_code = r1_res.status_code
            
            res_data = r1_res.json()
            # Normalize token key if Repo 1 uses 'token' instead of 'access_token'
            if "token" in res_data and "access_token" not in res_data:
                res_data["access_token"] = res_data["token"]
                
            logger.info(
                f"Repo 1 login → HTTP {r1_res.status_code}. "
                f"Keys: {list(res_data.keys())}. "
                f"Has token: {'access_token' in res_data}"
            )
            return res_data
        except Exception as exc:
            logger.error(f"Proxy login failed: {exc}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Authentication server unreachable: {exc}",
            )



@router.post("/logout", dependencies=[Depends(verify_admin_or_superadmin)])
async def proxy_logout(request: Request):
    """Proxy logout to Repo 1 — invalidates the JWT on Repo 1's side."""
    auth_header = request.headers.get("Authorization", "")
    headers = {"X-Admin-Key": _get_admin_key(), "Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    
    repo1_base = _get_repo1_base()
    url = f"{repo1_base}/admin/logout" # Default fallback

    # Check the JWT to see if this is a tenant user or superadmin
    if auth_header and auth_header.startswith("Bearer "):
        try:
            from jose import jwt
            token = auth_header.split(" ")[1]
            # We don't need to verify the signature strictly here just to route the logout,
            # but we can use the configured secret if available.
            secret = getattr(config, "secret_key", "")
            payload = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_signature": False})
            
            user_type = payload.get("user_type", "")
            if user_type == "tenant_user":
                url = f"{repo1_base}/tenant/logout"
                logger.info(f"Routing to Tenant Logout: {url}")
            else:
                logger.info(f"Routing to Admin Logout: {url}")
        except Exception as e:
            logger.warning(f"Could not parse JWT for logout routing, falling back to /admin/logout: {e}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(url, headers=headers)
            return response.json()
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Identity server unreachable: {exc}")


@router.get("/auth/jwt-public-config", dependencies=[Depends(verify_admin_or_superadmin)])
async def get_jwt_public_config():
    """Return Repo 1's JWT algorithm / expiry config (for Repo 2 to verify alignment)."""
    return await _repo1_request("GET", "/admin/auth/jwt-public-config")


@router.get("/config/verify-sync", dependencies=[Depends(verify_admin_or_superadmin)])
async def verify_repo1_sync():
    """Diagnostic: Check if SECRET_KEY and config are aligned with Repo 1."""
    try:
        data = await _repo1_request("GET", "/admin/auth/jwt-public-config")
        local_secret = getattr(config, "secret_key", None) or os.getenv("SECRET_KEY", "")
        return {
            "status": "success",
            "repo1_config": data,
            "local_secret_len": len(local_secret) if local_secret else 0,
            "local_secret_suffix": local_secret[-4:] if local_secret else "NONE",
            "env_var_match": data.get("secret_env_var") == "SECRET_KEY",
            "alg_match": data.get("algorithm") == "HS256",
        }
    except HTTPException as exc:
        return {"status": "error", "detail": exc.detail}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


# ==========================================================================
# Tenant CRUD proxy → Repo 1
# ==========================================================================

@router.get("/tenants", dependencies=[Depends(verify_admin_or_superadmin)])
async def list_tenants(
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
):
    """List all tenants from Repo 1."""
    params = {"page": page, "page_size": page_size}
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    return await _repo1_request("GET", "/admin/tenants", params=params)


@router.post("/tenants", dependencies=[Depends(verify_admin_or_superadmin)])
async def create_tenant(payload: dict):
    """Create a new tenant in Repo 1. Fires tenant.created webhook back to Repo 2."""
    return await _repo1_request("POST", "/admin/tenants", body=payload)


@router.get("/tenants/{tenant_id}", dependencies=[Depends(verify_admin_or_superadmin)])
async def get_tenant(tenant_id: str):
    """Get full tenant detail from Repo 1."""
    return await _repo1_request("GET", f"/admin/tenants/{tenant_id}")


@router.put("/tenants/{tenant_id}", dependencies=[Depends(verify_admin_or_superadmin)])
async def update_tenant(tenant_id: str, payload: dict):
    """Update a tenant in Repo 1. Fires tenant.updated webhook back to Repo 2."""
    return await _repo1_request("PUT", f"/admin/tenants/{tenant_id}", body=payload)


@router.delete("/tenants/{tenant_id}", dependencies=[Depends(verify_admin_or_superadmin)])
async def delete_tenant(tenant_id: str):
    """Soft-delete a tenant in Repo 1. Fires tenant.deleted webhook back to Repo 2."""
    return await _repo1_request("DELETE", f"/admin/tenants/{tenant_id}")


# ==========================================================================
# User CRUD proxy → Repo 1
# ==========================================================================

@router.get("/users", dependencies=[Depends(verify_admin_or_superadmin)])
async def list_users(
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
):
    """List all users from Repo 1."""
    params = {"page": page, "page_size": page_size}
    if tenant_id:
        params["tenant_id"] = tenant_id
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    return await _repo1_request("GET", "/admin/users", params=params)


@router.post("/users", dependencies=[Depends(verify_admin_or_superadmin)])
async def create_user(payload: dict):
    """Create a user in Repo 1 (password required, bcrypt-hashed server-side)."""
    return await _repo1_request("POST", "/admin/users", body=payload)


@router.delete("/users/{username}", dependencies=[Depends(verify_admin_or_superadmin)])
async def delete_user(username: str):
    """Soft-delete a user by username in Repo 1."""
    return await _repo1_request("DELETE", f"/admin/users/{username}")


# ==========================================================================
# IP Allowlist proxy → Repo 1
# ==========================================================================

@router.get("/allowlist/{tenant_id}", dependencies=[Depends(verify_admin_or_superadmin)])
async def get_ip_allowlist(tenant_id: str):
    """
    Get the runtime flat IP allowlist for a tenant from Repo 1.

    Returns both the flat ip_ranges list (used by the pipeline) and
    the rich entries list (for the dashboard).
    """
    data = await _repo1_request("GET", f"/admin/allowlist/{tenant_id}")
    # Normalise to a consistent shape for the Repo 2 dashboard
    return {
        "status": "success",
        "tenant_id": tenant_id,
        "total": data.get("total", len(data.get("ip_ranges", []))),
        "ips": data.get("ip_ranges", []),
        "entries": data.get("entries", []),
    }


@router.get("/tenants/{tenant_id}/ips", dependencies=[Depends(verify_admin_or_superadmin)])
async def get_tenant_ips(tenant_id: str):
    """Get rich IP metadata for a tenant from Repo 1."""
    return await _repo1_request("GET", f"/admin/tenants/{tenant_id}/ips")


@router.post("/tenants/{tenant_id}/ips", dependencies=[Depends(verify_admin_or_superadmin)])
async def add_tenant_ip(tenant_id: str, payload: dict):
    """Add an IP / CIDR range to a tenant's allowlist in Repo 1."""
    return await _repo1_request("POST", f"/admin/tenants/{tenant_id}/ips", body=payload)


@router.delete("/tenants/{tenant_id}/ips/{ip_id}", dependencies=[Depends(verify_admin_or_superadmin)])
async def remove_tenant_ip(tenant_id: str, ip_id: str):
    """Remove an IP entry from a tenant's allowlist in Repo 1."""
    return await _repo1_request("DELETE", f"/admin/tenants/{tenant_id}/ips/{ip_id}")


# Keep legacy allowlist delete route for backward compatibility
@router.delete("/allowlist/{tenant_id}/{ip:path}", dependencies=[Depends(verify_admin_or_superadmin)])
async def remove_from_allowlist_legacy(tenant_id: str, ip: str):
    """Legacy route: remove an IP from allowlist. Prefer /tenants/{id}/ips/{ip_id}."""
    return await _repo1_request("DELETE", f"/admin/allowlist/{tenant_id}/{ip}")


# ==========================================================================
# API Keys proxy → Repo 1
# ==========================================================================

@router.post("/tenants/{tenant_id}/api-keys", dependencies=[Depends(verify_admin_or_superadmin)])
async def create_api_key(tenant_id: str, payload: dict):
    """Create an API key for a tenant in Repo 1."""
    return await _repo1_request("POST", f"/admin/tenants/{tenant_id}/api-keys", body=payload)


@router.get("/tenants/{tenant_id}/api-keys", dependencies=[Depends(verify_admin_or_superadmin)])
async def list_api_keys(tenant_id: str):
    """List all API keys for a tenant from Repo 1."""
    return await _repo1_request("GET", f"/admin/tenants/{tenant_id}/api-keys")


@router.delete("/api-keys/{key_id}", dependencies=[Depends(verify_admin_or_superadmin)])
async def revoke_api_key(key_id: str):
    """Revoke an API key in Repo 1."""
    return await _repo1_request("DELETE", f"/admin/api-keys/{key_id}")


# ==========================================================================
# Webhook configuration proxy → Repo 1
# ==========================================================================

@router.post("/webhooks/configure", dependencies=[Depends(verify_admin_or_superadmin)])
async def configure_webhook(payload: dict):
    """Set or override the webhook URL that Repo 1 sends tenant events to."""
    return await _repo1_request("POST", "/admin/webhooks/configure", body=payload)


@router.get("/webhooks/status", dependencies=[Depends(verify_admin_or_superadmin)])
async def get_webhook_status():
    """Get the currently active webhook configuration from Repo 1."""
    return await _repo1_request("GET", "/admin/webhooks/status")


@router.delete("/webhooks/configure", dependencies=[Depends(verify_admin_or_superadmin)])
async def delete_webhook_override():
    """Remove the webhook URL override — Repo 1 reverts to the default derived URL."""
    return await _repo1_request("DELETE", "/admin/webhooks/configure")


# ==========================================================================
# Audit log proxy → Repo 1
# ==========================================================================

@router.get("/audit-log", dependencies=[Depends(verify_admin_or_superadmin)])
async def get_audit_log(
    page: int = 1,
    page_size: int = 20,
    tenant_id: Optional[str] = None,
):
    """Retrieve the admin audit log from Repo 1."""
    params: dict = {"page": page, "page_size": page_size}
    if tenant_id:
        params["tenant_id"] = tenant_id
    return await _repo1_request("GET", "/admin/audit-log", params=params)


# ==========================================================================
# Generic catch-all proxy (for any Repo 1 /admin/* path not explicitly listed)
# ==========================================================================

@router.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_repo1(
    path: str,
    request: Request,
    _auth=Depends(verify_admin_or_superadmin),
):
    """
    Generic proxy for any Repo 1 admin endpoint not explicitly mapped above.
    Forwards the request using the service account X-Admin-Key.
    """
    repo1_base = _get_repo1_base()
    target_url = f"{repo1_base}/{path}"
    headers = {
        "Content-Type": "application/json",
        "X-Admin-Key": _get_admin_key(),
    }
    # Also forward Bearer token if present (for Repo 1 JWT auth)
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            logger.info(f"Proxying {request.method} /{path} → {target_url}")
            body = None
            if request.method in ("POST", "PUT"):
                try:
                    body = await request.json()
                except Exception:
                    body = None

            # Forward query params
            params = dict(request.query_params)

            response = await client.request(
                method=request.method,
                url=target_url,
                json=body,
                headers=headers,
                params=params,
                timeout=10.0,
            )
            try:
                return response.json()
            except Exception:
                return {"detail": response.text}

        except Exception as exc:
            logger.error(f"Proxy request to /{path} failed: {exc}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Repo 1 unreachable: {exc}",
            )
