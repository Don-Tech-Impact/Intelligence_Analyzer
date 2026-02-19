"""V1 Asset Service for device inventory management."""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from src.models.database import NormalizedLog, Alert
from src.core.database import db_manager

logger = logging.getLogger(__name__)


class AssetService:
    """Service for managing discovered assets."""

    @staticmethod
    def get_assets(
        tenant_id: str,
        db: Session,
        page: int = 1,
        limit: int = 20,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get asset inventory derived from logs.
        
        Assets are discovered from unique device_id values in logs.
        """
        # Base query for unique device_ids
        query = db.query(
            NormalizedLog.device_id,
            NormalizedLog.vendor,
            func.max(NormalizedLog.timestamp).label('last_seen'),
            func.count(NormalizedLog.id).label('event_count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id.isnot(None)
        ).group_by(
            NormalizedLog.device_id,
            NormalizedLog.vendor
        )

        # Apply search filter
        if search:
            query = query.filter(
                NormalizedLog.device_id.ilike(f"%{search}%")
            )

        # Get total count for pagination
        total = query.count()

        # Apply pagination
        offset = (page - 1) * limit
        results = query.order_by(desc('last_seen')).offset(offset).limit(limit).all()

        # Get threat counts for each device
        threat_counts = db.query(
            NormalizedLog.device_id,
            func.count(NormalizedLog.id).label('threat_count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id.isnot(None),
            NormalizedLog.severity.in_(['critical', 'high'])
        ).group_by(NormalizedLog.device_id).all()

        threat_map = {t.device_id: t.threat_count for t in threat_counts}

        assets = []
        for r in results:
            # Infer asset type from vendor
            asset_type = AssetService._infer_asset_type(r.vendor)
            
            assets.append({
                "device_id": r.device_id,
                "hostname": r.device_id,  # Use device_id as hostname for V1
                "type": asset_type,
                "vendor": r.vendor or "unknown",
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "event_count": r.event_count,
                "threat_count": threat_map.get(r.device_id, 0)
            })

        return {
            "data": assets,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "has_more": offset + limit < total
            }
        }

    @staticmethod
    def _infer_asset_type(vendor: Optional[str]) -> str:
        """Infer asset type from vendor name."""
        if not vendor:
            return "unknown"
        
        vendor_lower = vendor.lower()
        
        type_keywords = {
            "firewall": ["fortinet", "palo", "checkpoint", "firewall", "fortigate"],
            "switch": ["cisco", "juniper", "arista", "switch"],
            "server": ["windows", "linux", "server", "vmware"],
            "endpoint": ["endpoint", "workstation", "laptop", "desktop"],
            "router": ["router", "mikrotik"],
            "waf": ["waf", "cloudflare", "akamai"]
        }

        for asset_type, keywords in type_keywords.items():
            if any(kw in vendor_lower for kw in keywords):
                return asset_type

        return "other"

    @staticmethod
    def get_asset_details(
        tenant_id: str,
        device_id: str,
        db: Session
    ) -> Optional[Dict[str, Any]]:
        """Get detailed information for a single asset."""
        # Basic asset info
        asset_info = db.query(
            NormalizedLog.device_id,
            NormalizedLog.vendor,
            func.min(NormalizedLog.timestamp).label('first_seen'),
            func.max(NormalizedLog.timestamp).label('last_seen'),
            func.count(NormalizedLog.id).label('event_count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id == device_id
        ).group_by(
            NormalizedLog.device_id,
            NormalizedLog.vendor
        ).first()

        if not asset_info:
            return None

        # Severity distribution
        severity_dist = db.query(
            NormalizedLog.severity,
            func.count(NormalizedLog.id).label('count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id == device_id
        ).group_by(NormalizedLog.severity).all()

        # Recent alerts for this device
        recent_alerts = db.query(Alert).filter(
            Alert.tenant_id == tenant_id,
            Alert.details['device_id'].astext == device_id
        ).order_by(desc(Alert.created_at)).limit(5).all()

        # Top source IPs
        top_sources = db.query(
            NormalizedLog.source_ip,
            func.count(NormalizedLog.id).label('count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id == device_id,
            NormalizedLog.source_ip.isnot(None)
        ).group_by(NormalizedLog.source_ip).order_by(desc('count')).limit(5).all()

        return {
            "device_id": asset_info.device_id,
            "hostname": asset_info.device_id,
            "type": AssetService._infer_asset_type(asset_info.vendor),
            "vendor": asset_info.vendor or "unknown",
            "first_seen": asset_info.first_seen.isoformat() if asset_info.first_seen else None,
            "last_seen": asset_info.last_seen.isoformat() if asset_info.last_seen else None,
            "event_count": asset_info.event_count,
            "severity_distribution": {s: c for s, c in severity_dist},
            "top_source_ips": [{"ip": s.source_ip, "count": s.count} for s in top_sources],
            "recent_alerts": [
                {
                    "id": a.id,
                    "type": a.alert_type,
                    "severity": a.severity,
                    "created_at": a.created_at.isoformat()
                }
                for a in recent_alerts
            ]
        }

    @staticmethod
    def get_asset_summary(tenant_id: str, db: Session) -> Dict[str, Any]:
        """Get summary statistics for assets."""
        # Total unique devices
        total_assets = db.query(func.count(func.distinct(NormalizedLog.device_id))).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id.isnot(None)
        ).scalar() or 0

        # Assets by type (inferred from vendor)
        vendors = db.query(
            NormalizedLog.vendor,
            func.count(func.distinct(NormalizedLog.device_id)).label('count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id.isnot(None)
        ).group_by(NormalizedLog.vendor).all()

        # Group by inferred type
        type_counts = {}
        for v in vendors:
            asset_type = AssetService._infer_asset_type(v.vendor)
            type_counts[asset_type] = type_counts.get(asset_type, 0) + v.count

        # Assets with threats (last 24h)
        last_24h = datetime.utcnow() - timedelta(hours=24)
        assets_with_threats = db.query(func.count(func.distinct(NormalizedLog.device_id))).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.device_id.isnot(None),
            NormalizedLog.severity.in_(['critical', 'high']),
            NormalizedLog.timestamp >= last_24h
        ).scalar() or 0

        return {
            "total": total_assets,
            "by_type": type_counts,
            "with_threats": assets_with_threats,
            "healthy": total_assets - assets_with_threats
        }
