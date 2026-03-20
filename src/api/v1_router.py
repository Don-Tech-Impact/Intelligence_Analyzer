"""V1 API Router for afric-analyzer frontend."""

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import create_engine, desc, func, text
from sqlalchemy.orm import Session

from src.api.auth import verify_jwt
from src.core.config import config as siem_config
from src.core.database import db_manager
from src.models.database import Alert, ManagedDevice, NormalizedLog, Report
from src.models.schemas import ApiResponse
from src.services.analytics import AnalyticsService
from src.services.assets import AssetService
from src.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


# Create V1 router (protected by JWT)
# Create V1 router (protected by JWT)
router = APIRouter(
    prefix="/api/v1",
    tags=["V1 API"],
    dependencies=[Depends(verify_jwt)],
    redirect_slashes=False,  # Added to prevent 307 redirects/405s on trailing slashes
)


# Dependency for getting DB session
def get_db():
    with db_manager.session_scope() as session:
        yield session


# Secure dependency to get tenant ID from JWT or Query
def get_tenant_id(tenant_id: str = Query("default"), payload: dict = Depends(verify_jwt)) -> str:
    """
    Returns the tenant_id scoped to the current user.
    - If user is a regular tenant user: ALWAYS use their token's tenant_id.
    - If user is a superadmin: Use query parameter (allows oversight).
    """
    # Check if superadmin
    role = payload.get("role", "").lower()
    is_admin = payload.get("is_admin", False)
    admin_obj = payload.get("admin", {})
    if isinstance(admin_obj, dict):
        role = role or admin_obj.get("role", "").lower()
        is_admin = is_admin or admin_obj.get("is_admin", False)

    is_super = role == "superadmin" or is_admin is True

    # If not superadmin, strictly enforce token-based scoping and existence
    if not is_super:
        token_tenant = payload.get("tenant_id") or payload.get("sub")
        if token_tenant:
            # We use a direct engine/session here to keep this dependency lightweight
            # and to avoid interfering with FastAPI's primary 'get_db' generator.
            from sqlalchemy import create_engine
            from sqlalchemy.orm import Session as SyncSession

            from src.models.database import Tenant
            
            try:
                engine = create_engine(siem_config.database_url)
                # Use a safer, independent connection to prevent session cross-talk
                with engine.connect() as conn:
                    result = conn.execute(
                        text("SELECT tenant_id, is_active FROM tenants WHERE tenant_id = :tid"),
                        # text("SELECT id, is_active FROM tenants WHERE id = :tid"),
                        {"tid": token_tenant} # Use token_tenant here, not tenant_id from query
                    ).fetchone()
                    
                    if not result:
                        logger.warning(f"Access denied: Tenant '{token_tenant}' not found in database.")
                        raise HTTPException(status_code=403, detail="Tenant access denied or not provisioned.")
                    
                    if not result[1]: # is_active
                        logger.warning(f"Access denied: Tenant '{token_tenant}' is suspended.")
                        raise HTTPException(status_code=403, detail="Tenant account is suspended.")
                        
                    return token_tenant
            except HTTPException:
                raise
            except Exception as db_err:
                logger.error(f"Tenant verification CRASHED: {db_err}")
                raise HTTPException(
                    status_code=500, 
                    detail="Identity verification system is currently unavailable. Please try again in 30 seconds."
                )

    # For superadmins, default can be used if no query param
    return tenant_id


# ============================================
# Dashboard Endpoints
# ============================================


@router.get("/dashboard/summary")
def get_dashboard_summary(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """
    Get comprehensive dashboard summary.

    Returns:
        - Total events with trend
        - Active threats by severity
        - Affected assets
        - Risk score with factors
    """
    data = AnalyticsService.get_dashboard_summary(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/dashboard/bundle")
def get_dashboard_bundle(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """
    Consolidated endpoint for all dashboard data.
    Reduces network round-trips for slow connections.
    """
    summary = AnalyticsService.get_dashboard_summary(tenant_id, db)
    timeline = AnalyticsService.get_timeline(tenant_id, db)
    top_ips = AnalyticsService.get_top_ips(tenant_id, db)
    traffic = AnalyticsService.get_traffic_analysis(tenant_id, db)
    business = AnalyticsService.get_business_insights(tenant_id, db)

    # Recent alerts
    alerts_query = db.query(Alert).filter(Alert.tenant_id == tenant_id)
    recent_alerts = alerts_query.order_by(Alert.created_at.desc()).limit(10).all()

    return ApiResponse(
        status="success",
        data={
            "summary": summary,
            "timeline": timeline,
            "top_ips": top_ips,
            "traffic": traffic,
            "business": business,
            "recent_alerts": [
                (
                    a.to_dict()
                    if hasattr(a, "to_dict")
                    else {
                        "id": a.id,
                        "tenant_id": a.tenant_id,
                        "alert_type": a.alert_type,
                        "severity": a.severity,
                        "status": a.status,
                        "description": a.description,
                        "source_ip": a.source_ip,
                        "created_at": a.created_at.isoformat() if a.created_at else None,
                    }
                )
                for a in recent_alerts
            ],
        },
    )


# ============================================
# Log Endpoints
# ============================================


@router.get("/logs")
def list_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    device_type: Optional[str] = None,
    search: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    """
    List normalized logs with filters and pagination.
    """
    query = db.query(NormalizedLog).filter(NormalizedLog.tenant_id == tenant_id)

    if severity:
        query = query.filter(NormalizedLog.severity == severity)
    if vendor:
        query = query.filter(NormalizedLog.vendor == vendor)
    if device_type:
        query = query.filter(NormalizedLog.log_type == device_type)
    if search:
        query = query.filter((NormalizedLog.message.contains(search)) | (NormalizedLog.raw_data.contains(search)))

    total = query.count()
    offset = (page - 1) * limit
    logs = query.order_by(NormalizedLog.timestamp.desc()).offset(offset).limit(limit).all()

    data = [log.to_dict() for log in logs]

    return {
        "status": "success",
        "data": data,
        "pagination": {"page": page, "limit": limit, "total": total, "has_more": offset + limit < total},
        "timestamp": datetime.utcnow().isoformat(),
    }


# ============================================
# Analytics Endpoints
# ============================================


@router.get("/analytics/timeline")
def get_timeline(
    range: str = Query("24h", pattern="^(24h|7d|30d)$"),
    bucket: str = Query("hour", pattern="^(hour|day)$"),
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Get event timeline for charts.

    Args:
        range: Time range (24h, 7d, 30d)
        bucket: Aggregation bucket (hour, day)
    """
    data = AnalyticsService.get_timeline(tenant_id, db, range, bucket)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/threat-vectors")
def get_threat_vectors(
    limit: int = Query(10, ge=1, le=50), tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)
):
    """
    Get top threat vectors by alert type.

    Returns top N threat types with counts and trends.
    """
    data = AnalyticsService.get_threat_vectors(tenant_id, db, limit)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/geo-distribution")
def get_geo_distribution(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """
    Get geographic distribution of events.

    Returns country breakdown with event and threat counts.
    """
    data = AnalyticsService.get_geo_distribution(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/traffic")
def get_traffic_analysis(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """
    Get network traffic analysis by protocol.

    Note: Byte counts are estimated for V1.
    """
    data = AnalyticsService.get_traffic_analysis(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/top-ips")
def get_top_ips(
    limit: int = Query(10, ge=1, le=50), tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)
):
    """Get top source/destination IPs."""
    # We can reuse logic or call root-level logic if we had it in a service.
    # For now, let's implement via a quick query or use logic from existing root endpoint.
    results = (
        db.query(NormalizedLog.source_ip, func.count(NormalizedLog.id).label("count"))
        .filter(NormalizedLog.tenant_id == tenant_id, NormalizedLog.source_ip.isnot(None))
        .group_by(NormalizedLog.source_ip)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    data = [{"ip": r.source_ip, "count": r.count} for r in results]
    return ApiResponse(status="success", data=data)


@router.get("/analytics/business-insights")
async def get_business_insights(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """Get insights on business vs after-hours activity."""
    # Attempt to fetch tenant config for business hours
    tenant_config: Dict[str, Any] = {}
    try:
        repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
        admin_key = os.getenv("ADMIN_KEY") or "changeme-admin-key"
        async with httpx.AsyncClient(timeout=2.0) as client:
            res = await client.get(f"{repo1_url}/admin/tenants/{tenant_id}", headers={"X-Admin-Key": admin_key})
            if res.status_code == 200:
                tenant_data = res.json()
                tenant_config = tenant_data.get("config") or tenant_data.get("settings") or {}
    except Exception as e:
        logger.warning(f"Could not fetch tenant config for business hours: {e}")

    data = AnalyticsService.get_business_insights(tenant_id, db, config=tenant_config)
    return ApiResponse(status="success", data=data)


# ============================================
# Alert Endpoints (Enhanced)
# ============================================


@router.get("/alerts")
def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
    status: Optional[str] = Query(None, pattern="^(open|investigating|resolved|dismissed)$"),
    alert_type: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    """
    List alerts with filters and pagination.
    """
    query = db.query(Alert).filter(Alert.tenant_id == tenant_id)

    # Apply filters
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * limit
    alerts = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()

    data = [
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "description": a.description,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "notified": a.notified,
        }
        for a in alerts
    ]

    return {
        "status": "success",
        "data": data,
        "pagination": {"page": page, "limit": limit, "total": total, "has_more": offset + limit < total},
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: int, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """
    Get detailed alert information including related logs.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.tenant_id == tenant_id).first()

    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # Get related logs (same source_ip, within 1 hour)
    from datetime import timedelta

    time_window = timedelta(hours=1)
    start_time = alert.created_at - time_window
    end_time = alert.created_at + time_window

    related_logs = (
        db.query(NormalizedLog)
        .filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.source_ip == alert.source_ip,
            NormalizedLog.timestamp >= start_time,
            NormalizedLog.timestamp <= end_time,
        )
        .order_by(NormalizedLog.timestamp.desc())
        .limit(20)
        .all()
    )

    # Generate recommendations based on alert type
    recommendations = _generate_recommendations(str(alert.alert_type), str(alert.severity))

    return ApiResponse(
        status="success",
        data={
            "id": alert.id,
            "type": alert.alert_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "description": alert.description,
            "status": alert.status,
            "details": alert.details,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "notified": alert.notified,
            "related_logs": [
                {
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "source_ip": log.source_ip,
                    "destination_ip": log.destination_ip,
                    "message": log.message[:200] if log.message else None,
                    "severity": log.severity,
                }
                for log in related_logs
            ],
            "recommendations": recommendations,
        },
    )


def _generate_recommendations(alert_type: str, severity: str) -> list:
    """Generate simple recommendations based on alert type."""
    recommendations_map = {
        "brute_force": [
            "Block the source IP at the firewall",
            "Enable account lockout policies",
            "Implement MFA for affected accounts",
            "Review authentication logs for successful logins",
        ],
        "port_scan": [
            "Block the source IP",
            "Review exposed services",
            "Enable IDS/IPS rules for port scanning",
            "Check for follow-up exploitation attempts",
        ],
        "suspicious_payload": [
            "Quarantine the affected payload",
            "Scan systems for indicators of compromise",
            "Update antivirus signatures",
            "Review network traffic for data exfiltration",
        ],
        "beaconing": [
            "Block the destination IP/domain",
            "Scan affected host for malware",
            "Review process execution logs",
            "Check for lateral movement",
        ],
        "threat_intel_match": [
            "Block the matched indicator",
            "Investigate all related traffic",
            "Scan for additional IoCs",
            "Report to threat intelligence team",
        ],
    }

    base_recommendations = recommendations_map.get(
        alert_type, ["Investigate the alert", "Block suspicious IPs", "Review related logs"]
    )

    if severity in ["critical", "high"]:
        base_recommendations.insert(0, "⚠️ IMMEDIATE ACTION REQUIRED")

    return base_recommendations


# ============================================
# Asset Endpoints
# ============================================


@router.get("/assets/summary")
def get_asset_summary(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """Get asset inventory summary."""
    data = AssetService.get_asset_summary(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/assets/managed")
def list_managed_devices(tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """List all formally registered devices for this tenant."""
    devices = db.query(ManagedDevice).filter(ManagedDevice.tenant_id == tenant_id).all()
    results = []
    now = datetime.utcnow()
    for d in devices:
        dict_d = d.to_dict()
        is_online = d.last_log_at and (now - d.last_log_at) < timedelta(minutes=10)
        dict_d["is_online"] = bool(is_online)
        results.append(dict_d)
    return ApiResponse(status="success", data=results)


@router.post("/assets/managed")
async def register_device(payload: dict, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """
    Register a new managed device.
    Also automatically adds the IP to the Repo 1 allowlist.
    """
    try:
        name = payload.get("name") or payload.get("device_name")
        ip = payload.get("ip_address")
        if not name or not ip:
            raise HTTPException(status_code=400, detail="Name and IP Address are required")

        # 1. Create locally
        device = ManagedDevice(
            tenant_id=tenant_id,
            name=name,
            ip_address=ip,
            device_id=payload.get("device_id"),
            category=payload.get("category", "other"),
            description=payload.get("description"),
        )
        db.add(device)
        db.commit()

        # 2. Sync with Redis Allowlist (Repo 1 Standard)
        sync_status = "pending"
        sync_error = None
        try:
            from src.services.redis_client import redis_client
            redis_key = f"ip_allowlist:{tenant_id}:devices"
            
            # Use SADD for the allowlist set
            redis_client.sadd(redis_key, ip)
            logger.info(f"[SIEM] IP {ip} added to Redis allowlist for tenant {tenant_id}")
            sync_status = "success"
        except Exception as sync_err:
            sync_status = "failed_redis"
            sync_error = str(sync_err)
            logger.error(f"[SIEM] Device registered locally but failed to sync Redis allowlist: {sync_err}")

        res_data = device.to_dict()
        res_data["sync_status"] = sync_status
        if sync_error:
            res_data["sync_error"] = sync_error
            
        return ApiResponse(status="success", data=res_data)
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"[SIEM] Device registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/assets/managed/{device_id_int}")
def delete_managed_device(device_id_int: int, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """Unregister a managed device."""
    device = (
        db.query(ManagedDevice).filter(ManagedDevice.id == device_id_int, ManagedDevice.tenant_id == tenant_id).first()
    )

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    ip_to_remove = device.ip_address
    
    # 1. Remove from PostgreSQL
    db.delete(device)
    db.commit()

    # 2. Remove from Redis Allowlist
    from src.services.redis_client import redis_client
    redis_key = f"ip_allowlist:{tenant_id}:devices"
    try:
        redis_client.srem(redis_key, ip_to_remove)
        logger.info(f"[SIEM] IP {ip_to_remove} removed from Redis allowlist for {tenant_id}")
    except Exception as e:
        logger.error(f"[SIEM] Failed to remove IP from Redis: {e}")

    return ApiResponse(status="success", message="Device unregistered and removed from allowlist")


@router.get("/assets/discovered")
def list_discovered_assets(
    tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db), page: int = 1, limit: int = 20
):
    """Returns unique assets discovered from logs that are NOT yet in managed_devices."""
    # Get all managed identifiers (both IPs and Correlation IDs)
    managed_devices = (
        db.query(ManagedDevice.ip_address, ManagedDevice.device_id).filter(ManagedDevice.tenant_id == tenant_id).all()
    )
    managed_identifiers = set()
    for d in managed_devices:
        if d.ip_address:
            managed_identifiers.add(d.ip_address)
        if d.device_id:
            managed_identifiers.add(d.device_id)

    all_assets = AssetService.get_assets(tenant_id, db, page, limit)

    # Filter: Only show assets where the identifier is NOT known as a managed device
    discovered = [a for a in all_assets["data"] if a["device_id"] not in managed_identifiers]
    return ApiResponse(status="success", data={"data": discovered, "pagination": all_assets["pagination"]})


@router.get("/assets")
def list_assets(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    """List discovered assets with pagination."""
    result = AssetService.get_assets(tenant_id, db, page, limit, search)
    return {"status": "success", **result, "timestamp": datetime.utcnow().isoformat()}


# ============================================
# User Device Management (Repo 1 Proxy)
# ============================================


@router.get("/assets/my-devices")
async def get_my_devices(request: Request):
    """Get registered devices for the current user from Repo 1."""
    repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
    auth_header = request.headers.get("Authorization")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            headers = {"Content-Type": "application/json"}
            if auth_header:
                headers["Authorization"] = auth_header

            response = await client.get(f"{repo1_url}/api/logs/my-devices", headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Repo 1 returned {response.status_code} for my-devices: {response.text}")
                return {"status": "error", "message": "Failed to fetch devices from identity server", "devices": []}
                
            return response.json()
        except Exception as e:
            logger.error(f"Failed to reach Repo 1 for devices: {e}")
            return {"status": "error", "message": f"Identity server unreachable: {e}", "devices": []}


@router.post("/assets/devices")
async def register_user_device(request: Request, payload: dict):
    """Register a personal device in Repo 1."""
    repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
    auth_header = request.headers.get("Authorization")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            headers = {"Content-Type": "application/json"}
            if auth_header:
                headers["Authorization"] = auth_header

            # Map frontend payload to Repo 1 spec (action-based)
            repo1_payload = {
                "action": "add",
                "device_ip": payload.get("device_ip") or payload.get("ip"),
                "device_name": payload.get("device_name") or payload.get("name"),
            }

            response = await client.post(f"{repo1_url}/api/logs/devices", json=repo1_payload, headers=headers)
            
            if response.status_code not in [200, 201]:
                logger.error(f"Repo 1 returned {response.status_code} for device registration: {response.text}")
                raise HTTPException(status_code=502, detail="Failed to register device with identity server")
                
            return response.json()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Identity server unreachable: {e}")


@router.delete("/assets/devices/{ip}")
async def remove_user_device(ip: str, request: Request):
    """Remove a registered device from Repo 1."""
    repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
    auth_header = request.headers.get("Authorization")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            headers = {"Content-Type": "application/json"}
            if auth_header:
                headers["Authorization"] = auth_header

            # Use the correct Repo 1 action pattern
            payload = {"action": "remove", "device_ip": ip}

            response = await client.post(f"{repo1_url}/api/logs/devices", json=payload, headers=headers)
            
            if response.status_code not in [200, 204]:
                 logger.error(f"Repo 1 returned {response.status_code} for device removal: {response.text}")
                 raise HTTPException(status_code=502, detail="Failed to remove device from identity server")
                 
            return response.json()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Identity server unreachable: {e}")


@router.get("/assets/primary-ip")
async def get_primary_ip(request: Request):
    """Get the primary office IP for the current tenant from Repo 1."""
    repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
    auth_header = request.headers.get("Authorization")

    # We need the tenant_id from the token to call the Repo 1 admin endpoint
    from src.api.auth import decode_token_payload

    token = auth_header.split(" ")[1] if auth_header and "Bearer " in auth_header else ""
    payload = decode_token_payload(token)
    tenant_id = payload.get("tenant_id") if payload else "default"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            # Repo 1 doesn't have a public "get-primary-ip" for users yet,
            # so we use the admin endpoint with the analyzer's admin key
            admin_key = os.getenv("ADMIN_KEY") or "changeme-admin-key"
            headers = {"X-Admin-Key": admin_key}

            response = await client.get(f"{repo1_url}/admin/tenants/{tenant_id}", headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Repo 1 returned {response.status_code} for tenant metadata: {response.text}")
                return {"status": "success", "primary_ip": "Not Set", "warning": "Tenant details unavailable"}

            data = response.json()

            # Extract IP info (support string, or list of strings from 'primary_ips')
            primary_ip = data.get("primary_ip") or data.get("office_ip")
            primary_ips = data.get("primary_ips", [])

            if not primary_ip and isinstance(primary_ips, list) and primary_ips:
                primary_ip = ", ".join(primary_ips)

            return {"status": "success", "primary_ip": primary_ip or "Not Set"}
        except Exception as e:
            logger.error(f"Failed to reach Repo 1 for metadata: {e}")
            return {"status": "success", "primary_ip": "Not Set", "error": str(e)}


@router.get("/assets/telemetry/{device_id}")
def get_asset_detail(device_id: str, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """Get detailed asset information."""
    data = AssetService.get_asset_details(tenant_id, device_id, db)
    if not data:
        raise HTTPException(status_code=404, detail="Asset not found")
    return ApiResponse(status="success", data=data)


# ============================================
# Report Endpoints
# ============================================


@router.get("/reports")
def list_reports(
    report_type: Optional[str] = None, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)
):
    """List reports for the current tenant."""
    query = db.query(Report).filter(Report.tenant_id == tenant_id)
    if report_type:
        query = query.filter(Report.report_type == report_type)

    reports = query.order_by(desc(Report.created_at)).all()
    data = []
    for r in reports:
        data.append(
            {
                "id": r.id,
                "report_type": r.report_type,
                "start_date": r.start_date.isoformat() if r.start_date else None,
                "end_date": r.end_date.isoformat() if r.end_date else None,
                "total_logs": r.total_logs,
                "total_alerts": r.total_alerts,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "format": r.format,
            }
        )
    return ApiResponse(status="success", data=data)


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """Download a specific report file."""
    report = db.query(Report).filter(Report.id == report_id, Report.tenant_id == tenant_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    import os

    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file missing on server")

    from fastapi.responses import FileResponse

    return FileResponse(report.file_path, filename=os.path.basename(report.file_path))


@router.get("/reports/{report_id}/content")
def get_report_content(report_id: int, tenant_id: str = Depends(get_tenant_id), db: Session = Depends(get_db)):
    """Get the HTML content of a report."""
    report = db.query(Report).filter(Report.id == report_id, Report.tenant_id == tenant_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    import os

    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file missing on server")

    with open(report.file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return ApiResponse(status="success", data={"html": content, "type": report.report_type})


@router.post("/reports/generate")
def generate_report(
    report_type: str = "daily",
    days_back: int = 1,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    """Trigger manual report generation."""
    try:
        gen = ReportGenerator()
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        report = gen.generate_report(start_date, end_date, report_type, tenant_id)
        if not report:
            raise HTTPException(status_code=500, detail="Failed to generate report")
        return ApiResponse(status="success", data={"report_id": report.id})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Configuration Endpoints
# ============================================


@router.get("/config")
def get_config(tenant_id: str = Depends(get_tenant_id)):
    """Get tenant-safe configuration thresholds."""
    return ApiResponse(
        status="success",
        data={
            "brute_force_threshold": siem_config.brute_force_threshold,
            "port_scan_threshold": siem_config.port_scan_threshold,
            "log_level": siem_config.log_level,
            "tenant_id": tenant_id,
        },
    )


@router.post("/config")
def update_config(new_config: dict, tenant_id: str = Depends(get_tenant_id)):
    """Update SIEM configuration symbols."""
    try:
        if "brute_force_threshold" in new_config:
            siem_config.set("detection.brute_force.threshold", int(new_config["brute_force_threshold"]))
        if "port_scan_threshold" in new_config:
            siem_config.set("detection.port_scan.threshold", int(new_config["port_scan_threshold"]))
        if "log_level" in new_config:
            siem_config.set("logging.level", new_config["log_level"])
        return ApiResponse(status="success", message="Configuration updated successfully")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Interactive Mocks: Metadata Proxy
# ============================================


@router.patch("/tenant/metadata")
async def update_tenant_metadata(request: Request, tenant_id: str = Depends(get_tenant_id)):
    """
    Proxies metadata updates (Compliance, Incident Response, Onboarding)
    from the dashboard directly to Repo 1's deep merge endpoint.
    """
    repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
    admin_key = os.getenv("ADMIN_KEY") or os.getenv("ADMIN_API_KEY") or "changeme-admin-key"

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            # We use the X-Admin-Key to bypass user auth on Repo 1 since
            # Repo 2 has already verified the user via get_tenant_id
            headers = {"Content-Type": "application/json", "X-Admin-Key": admin_key}

            res = await client.patch(f"{repo1_url}/admin/tenants/{tenant_id}/metadata", headers=headers, json=body)

            return Response(
                content=res.content, status_code=res.status_code, headers={"Content-Type": "application/json"}
            )
        except httpx.RequestError as e:
            logger.error(f"Failed to proxy metadata update to Repo 1: {e}")
            raise HTTPException(status_code=502, detail="Control plane unreachable")


@router.get("/tenant/metadata")
async def get_tenant_metadata(tenant_id: str = Depends(get_tenant_id)):
    """
    Proxies a request to Repo 1 to fetch the tenant's current settings/metadata.
    """
    # Use verified paths from Repo 1 Swagger: /admin/tenants/{tid}
    repo1_url = (os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080").rstrip('/')
    admin_key = os.getenv("ADMIN_KEY") or os.getenv("ADMIN_API_KEY") or "changeme-admin-key"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            headers = {"X-Admin-Key": admin_key}
            res = await client.get(f"{repo1_url}/admin/tenants/{tenant_id}", headers=headers)

            if res.status_code == 200:
                try:
                    data = res.json()
                    return ApiResponse(status="success", data=data)
                except Exception:
                    logger.error(f"Repo 1 returned non-JSON for tenant {tenant_id}")
                    raise HTTPException(status_code=502, detail="Upstream returned malformed response")

            if res.status_code == 404:
                # Fallback for new tenants without Repo 1 metadata yet
                return ApiResponse(
                    status="success", data={"config": {"compliance": [], "incident_response": {"channels": []}}}
                )

            logger.error(f"Repo 1 returned status {res.status_code} for tenant {tenant_id}")
            raise HTTPException(status_code=res.status_code, detail="Remote control plane error")

        except httpx.RequestError as e:
            logger.error(f"Failed to reach Repo 1 for metadata: {e}")
            raise HTTPException(status_code=502, detail="Control plane unreachable")
        except Exception as e:
            logger.error(f"Unexpected error in metadata proxy: {e}")
            raise HTTPException(status_code=500, detail="Internal proxy error")
