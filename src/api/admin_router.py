"""Admin API Router for service-to-service communication with Repo1.

Exposes per-tenant usage statistics and system overview endpoints.
Protected by X-Admin-Key header (shared secret between Repo1 and Repo2).
"""

import os
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert, Tenant, Report, DeadLetter
import httpx
from src.api.auth import verify_superadmin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["Admin (Service-to-Service)"])


# ---------- Auth ----------

def _get_admin_key() -> str:
    """Get the admin API key from environment."""
    return os.getenv("ADMIN_API_KEY", "changeme-admin-key")


def verify_admin_key(x_admin_key: str = Header(..., alias="X-Admin-Key")) -> str:
    """Validate X-Admin-Key header matches the configured secret."""
    expected = _get_admin_key()
    if x_admin_key != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin API key"
        )
    return x_admin_key

def verify_admin_or_superadmin(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    jwt_payload: Optional[dict] = Depends(verify_superadmin)
):
    """Allow either the service API key or a verified Superadmin JWT."""
    if x_admin_key:
        expected = _get_admin_key()
        if x_admin_key == expected:
            return True
    
    if jwt_payload:
        return True
        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication"
    )


# ---------- Dependencies ----------

def get_db():
    with db_manager.session_scope() as session:
        yield session


# ---------- Endpoints ----------

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
@router.post("/proxy/login")
async def proxy_login(payload: dict):
    """
    Proxy login request to Repo 1 to bypass browser CORS issues.
    This acts as a Bridge between Repo 2 Dashboard and Repo 1 API.
    """
    repo1_url = f"{os.getenv('REPO1_BASE_URL', 'http://host.docker.internal:8080')}/admin/login"
    
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Proxying login request to {repo1_url}")
            response = await client.post(
                repo1_url, 
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            return response.json()
        except Exception as e:
            logger.error(f"Proxy login failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Authentication server unreachable: {str(e)}"
            )

@router.post("/tenants/sync", dependencies=[Depends(verify_admin_key)])
async def sync_tenant(payload: dict, db: Session = Depends(get_db)):
    """
    Webhook endpoint for Repo 1 to synchronize tenant data.
    Handles tenant.created, tenant.updated, tenant.deleted.
    """
    event = payload.get("event")
    tenant_data = payload.get("tenant", {})
    tenant_id = tenant_data.get("tenant_id")
    
    if not event or not tenant_id:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")
    
    logger.info(f"Received sync event '{event}' for tenant '{tenant_id}'")
    
    # Check if tenant exists
    tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
    
    if event == "tenant.deleted":
        if tenant:
            tenant.is_active = False
            db.commit()
            return {"status": "success", "message": f"Tenant {tenant_id} deactivated"}
        return {"status": "ignored", "message": "Tenant not found"}
    
    # For created/updated
    if not tenant:
        tenant = Tenant(
            tenant_id=tenant_id,
            name=tenant_data.get("name", tenant_id),
            is_active=tenant_data.get("status") == "active"
        )
        db.add(tenant)
    else:
        tenant.name = tenant_data.get("name", tenant.name)
        tenant.is_active = tenant_data.get("status") == "active"
    
    db.commit()
    return {"status": "success", "message": f"Tenant {tenant_id} {event.split('.')[1]}d"}

@router.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_repo1(
    path: str, 
    request: Request,
    jwt_payload: dict = Depends(verify_superadmin), 
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")
):
    """
    Generic proxy for Repo 1 admin endpoints (Tenants, Users, etc.)
    Forward calls to Repo 1 while maintaining Superadmin protection.
    """
    repo1_base = os.getenv('REPO1_BASE_URL', 'http://host.docker.internal:8080')
    target_url = f"{repo1_base}/{path}"
    
    # Forward original auth header or use current token
    headers = {"Content-Type": "application/json"}
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header
    
    if x_admin_key:
        headers["X-Admin-Key"] = x_admin_key
        
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Proxying {request.method} {path} to {target_url}")
            
            # Get body if applicable
            body = None
            if request.method in ["POST", "PUT"]:
                try:
                    body = await request.json()
                except:
                    body = None

            response = await client.request(
                method=request.method,
                url=target_url,
                json=body,
                headers=headers,
                timeout=10.0
            )
            
            # Return Repo 1 response
            try:
                content = response.json()
            except:
                content = response.text
                
            return content
            
        except Exception as e:
            logger.error(f"Proxy request to {path} failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Repo 1 unreachable: {str(e)}"
            )

