"""V1 API Router for afric-analyzer frontend."""

from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import func, desc
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta

from src.core.database import db_manager
from src.models.database import Alert, NormalizedLog, Report, ManagedDevice
from src.services.analytics import AnalyticsService
from src.services.assets import AssetService
from src.services.report_generator import ReportGenerator
from src.models.schemas import ApiResponse
from src.api.auth import verify_jwt
from src.core.config import config as siem_config

# Create V1 router (protected by JWT)
# Create V1 router (protected by JWT)
router = APIRouter(
    prefix="/api/v1", 
    tags=["V1 API"], 
    dependencies=[Depends(verify_jwt)],
    redirect_slashes=False  # Added to prevent 307 redirects/405s on trailing slashes
)


# Dependency for getting DB session
def get_db():
    with db_manager.session_scope() as session:
        yield session


# Secure dependency to get tenant ID from JWT or Query
def get_tenant_id(
    tenant_id: str = Query("default"),
    payload: dict = Depends(verify_jwt)
) -> str:
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
    
    # If not superadmin, strictly enforce token-based scoping
    if not is_super:
        token_tenant = payload.get("tenant_id") or payload.get("sub")
        if token_tenant:
            return token_tenant
            
    return tenant_id


# ============================================
# Dashboard Endpoints
# ============================================

@router.get("/dashboard/summary")
def get_dashboard_summary(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
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
    db: Session = Depends(get_db)
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
        query = query.filter(NormalizedLog.device_type == device_type)
    if search:
        query = query.filter(
            (NormalizedLog.message.contains(search)) | 
            (NormalizedLog.raw_data.contains(search))
        )

    total = query.count()
    offset = (page - 1) * limit
    logs = query.order_by(NormalizedLog.timestamp.desc()).offset(offset).limit(limit).all()

    data = [log.to_dict() for log in logs]

    return {
        "status": "success",
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "has_more": offset + limit < total
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# ============================================
# Analytics Endpoints
# ============================================

@router.get("/analytics/timeline")
def get_timeline(
    range: str = Query("24h", pattern="^(24h|7d|30d)$"),
    bucket: str = Query("hour", pattern="^(hour|day)$"),
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
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
    limit: int = Query(10, ge=1, le=50),
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get top threat vectors by alert type.
    
    Returns top N threat types with counts and trends.
    """
    data = AnalyticsService.get_threat_vectors(tenant_id, db, limit)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/geo-distribution")
def get_geo_distribution(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get geographic distribution of events.
    
    Returns country breakdown with event and threat counts.
    """
    data = AnalyticsService.get_geo_distribution(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/traffic")
def get_traffic_analysis(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get network traffic analysis by protocol.
    
    Note: Byte counts are estimated for V1.
    """
    data = AnalyticsService.get_traffic_analysis(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/analytics/top-ips")
def get_top_ips(
    limit: int = Query(10, ge=1, le=50),
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """Get top source/destination IPs."""
    # We can reuse logic or call root-level logic if we had it in a service.
    # For now, let's implement via a quick query or use logic from existing root endpoint.
    results = db.query(
        NormalizedLog.source_ip,
        func.count(NormalizedLog.id).label('count')
    ).filter(
        NormalizedLog.tenant_id == tenant_id,
        NormalizedLog.source_ip.isnot(None)
    ).group_by(NormalizedLog.source_ip).order_by(desc('count')).limit(limit).all()
    
    data = [{"ip": r.source_ip, "count": r.count} for r in results]
    return ApiResponse(status="success", data=data)


@router.get("/analytics/business-insights")
def get_business_insights(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """Get insights on business vs after-hours activity."""
    data = AnalyticsService.get_business_insights(tenant_id, db)
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
    db: Session = Depends(get_db)
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
            "notified": a.notified
        }
        for a in alerts
    ]

    return {
        "status": "success",
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "has_more": offset + limit < total
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/alerts/{alert_id}")
def get_alert_detail(
    alert_id: int,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get detailed alert information including related logs.
    """
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == tenant_id
    ).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    # Get related logs (same source_ip, within 1 hour)
    from datetime import timedelta
    time_window = timedelta(hours=1)
    start_time = alert.created_at - time_window
    end_time = alert.created_at + time_window

    related_logs = db.query(NormalizedLog).filter(
        NormalizedLog.tenant_id == tenant_id,
        NormalizedLog.source_ip == alert.source_ip,
        NormalizedLog.timestamp >= start_time,
        NormalizedLog.timestamp <= end_time
    ).order_by(NormalizedLog.timestamp.desc()).limit(20).all()

    # Generate recommendations based on alert type
    recommendations = _generate_recommendations(alert.alert_type, alert.severity)

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
                    "severity": log.severity
                }
                for log in related_logs
            ],
            "recommendations": recommendations
        }
    )


def _generate_recommendations(alert_type: str, severity: str) -> list:
    """Generate simple recommendations based on alert type."""
    recommendations_map = {
        "brute_force": [
            "Block the source IP at the firewall",
            "Enable account lockout policies",
            "Implement MFA for affected accounts",
            "Review authentication logs for successful logins"
        ],
        "port_scan": [
            "Block the source IP",
            "Review exposed services",
            "Enable IDS/IPS rules for port scanning",
            "Check for follow-up exploitation attempts"
        ],
        "suspicious_payload": [
            "Quarantine the affected payload",
            "Scan systems for indicators of compromise",
            "Update antivirus signatures",
            "Review network traffic for data exfiltration"
        ],
        "beaconing": [
            "Block the destination IP/domain",
            "Scan affected host for malware",
            "Review process execution logs",
            "Check for lateral movement"
        ],
        "threat_intel_match": [
            "Block the matched indicator",
            "Investigate all related traffic",
            "Scan for additional IoCs",
            "Report to threat intelligence team"
        ]
    }

    base_recommendations = recommendations_map.get(alert_type, [
        "Investigate the alert",
        "Block suspicious IPs",
        "Review related logs"
    ])

    if severity in ["critical", "high"]:
        base_recommendations.insert(0, "⚠️ IMMEDIATE ACTION REQUIRED")

    return base_recommendations


# ============================================
# Asset Endpoints
# ============================================

@router.get("/assets/summary")
def get_asset_summary(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """Get asset inventory summary."""
    data = AssetService.get_asset_summary(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/assets/managed")
def list_managed_devices(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
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
async def register_device(
    payload: dict,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Register a new managed device. 
    Also automatically adds the IP to the Repo 1 allowlist.
    """
    try:
        name = payload.get("name")
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
            description=payload.get("description")
        )
        db.add(device)
        db.commit()

        # 2. Sync with Repo 1 Allowlist
        try:
            import httpx
            import os
            repo1_url = os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080"
            admin_key = os.getenv("ADMIN_KEY") or "changeme-admin-key"
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{repo1_url}/admin/tenants/{tenant_id}/ips",
                    json={
                        "ip_range": ip,
                        "label": f"Managed Device: {name}",
                        "is_active": True
                    },
                    headers={"X-Admin-Key": admin_key}
                )
        except Exception as sync_err:
            print(f"[SIEM] Device registered locally but failed to sync allowlist: {sync_err}")

        return ApiResponse(status="success", data=device.to_dict())
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/assets/managed/{device_id_int}")
def delete_managed_device(
    device_id_int: int,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """Unregister a managed device."""
    device = db.query(ManagedDevice).filter(
        ManagedDevice.id == device_id_int, 
        ManagedDevice.tenant_id == tenant_id
    ).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    db.delete(device)
    db.commit()
    return ApiResponse(status="success", message="Device unregistered")


@router.get("/assets/discovered")
def list_discovered_assets(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
    page: int = 1,
    limit: int = 20
):
    """Returns unique assets discovered from logs that are NOT yet in managed_devices."""
    managed_ips = [d.ip_address for d in db.query(ManagedDevice.ip_address).filter(ManagedDevice.tenant_id == tenant_id).all()]
    all_assets = AssetService.get_assets(tenant_id, db, page, limit)
    discovered = [a for a in all_assets["data"] if a["device_id"] not in managed_ips]
    return ApiResponse(status="success", data={
        "data": discovered,
        "pagination": all_assets["pagination"]
    })


@router.get("/assets")
def list_assets(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """List discovered assets with pagination."""
    result = AssetService.get_assets(tenant_id, db, page, limit, search)
    return {
        "status": "success",
        **result,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/assets/telemetry/{device_id}")
def get_asset_detail(
    device_id: str,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
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
    report_type: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """List reports for the current tenant."""
    query = db.query(Report).filter(Report.tenant_id == tenant_id)
    if report_type:
        query = query.filter(Report.report_type == report_type)
    
    reports = query.order_by(desc(Report.created_at)).all()
    data = []
    for r in reports:
        data.append({
            "id": r.id,
            "report_type": r.report_type,
            "start_date": r.start_date.isoformat() if r.start_date else None,
            "end_date": r.end_date.isoformat() if r.end_date else None,
            "total_logs": r.total_logs,
            "total_alerts": r.total_alerts,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "format": r.format
        })
    return ApiResponse(status="success", data=data)


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: int,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
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
def get_report_content(
    report_id: int,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """Get the HTML content of a report."""
    report = db.query(Report).filter(Report.id == report_id, Report.tenant_id == tenant_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    import os
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file missing on server")
        
    with open(report.file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    return ApiResponse(status="success", data={"html": content, "type": report.report_type})


@router.post("/reports/generate")
def generate_report(
    report_type: str = "daily",
    days_back: int = 1,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
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
    return ApiResponse(status="success", data={
        "brute_force_threshold": siem_config.brute_force_threshold,
        "port_scan_threshold": siem_config.port_scan_threshold,
        "log_level": siem_config.log_level,
        "tenant_id": tenant_id
    })


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
