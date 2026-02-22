"""V1 API Router for afric-analyzer frontend."""

from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import func, desc
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta

from src.core.database import db_manager
from src.models.database import Alert, NormalizedLog
from src.services.analytics import AnalyticsService
from src.services.assets import AssetService
from src.models.schemas import ApiResponse

# Create V1 router
router = APIRouter(prefix="/api/v1", tags=["V1 API"])


# Dependency for getting DB session
def get_db():
    with db_manager.session_scope() as session:
        yield session


# Tenant ID is passed as a query parameter (auth handled by Repo 1)
def get_tenant_id(tenant_id: str = Query("default")) -> str:
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

@router.get("/assets")
def list_assets(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    List discovered assets with pagination.
    """
    result = AssetService.get_assets(tenant_id, db, page, limit, search)
    return {
        "status": "success",
        **result,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/assets/summary")
def get_asset_summary(
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get asset inventory summary.
    """
    data = AssetService.get_asset_summary(tenant_id, db)
    return ApiResponse(status="success", data=data)


@router.get("/assets/{device_id}")
def get_asset_detail(
    device_id: str,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get detailed asset information.
    """
    data = AssetService.get_asset_details(tenant_id, device_id, db)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    return ApiResponse(status="success", data=data)
