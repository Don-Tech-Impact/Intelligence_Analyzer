"""V1 Analytics Service for dashboard and intelligence aggregations."""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import func, desc, and_
from sqlalchemy.orm import Session

from src.models.database import NormalizedLog, Alert, ThreatIntelligence
from src.core.database import db_manager

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service for computing analytics and aggregations."""

    @staticmethod
    def get_dashboard_summary(tenant_id: str, db: Session) -> Dict[str, Any]:
        """
        Get comprehensive dashboard summary.
        
        Returns:
            Dashboard summary with event counts, threat breakdown, risk score.
        """
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_48h = now - timedelta(hours=48)

        # Total events (last 14 days for demo/cold-start fallback)
        current_events = db.query(func.count(NormalizedLog.id)).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= last_24h
        ).scalar() or 0

        # Demo Fallback: If 0 logs in 24h, broaden to 14 days to show *something*
        if current_events == 0:
            current_events = db.query(func.count(NormalizedLog.id)).filter(
                NormalizedLog.tenant_id == tenant_id,
                NormalizedLog.timestamp >= (now - timedelta(days=14))
            ).scalar() or 0

        # Previous 24h for trend
        previous_events = db.query(func.count(NormalizedLog.id)).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= last_48h,
            NormalizedLog.timestamp < last_24h
        ).scalar() or 0

        # Calculate trend
        event_trend = 0.0
        if previous_events > 0:
            event_trend = ((current_events - previous_events) / previous_events) * 100

        # Active threats (open alerts)
        alerts_by_severity = db.query(
            Alert.severity,
            func.count(Alert.id)
        ).filter(
            Alert.tenant_id == tenant_id,
            Alert.status == 'open'
        ).group_by(Alert.severity).all()

        severity_map = {s: c for s, c in alerts_by_severity}
        total_threats = sum(severity_map.values())

        from sqlalchemy import cast, String
        # Affected assets (last 14 days)
        affected_assets = db.query(func.count(func.distinct(
            func.coalesce(NormalizedLog.device_id, cast(NormalizedLog.source_ip, String))
        ))).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= (now - timedelta(days=14))
        ).scalar() or 0

        # Asset types breakdown
        asset_types = db.query(
            NormalizedLog.vendor,
            func.count(func.distinct(func.coalesce(NormalizedLog.device_id, cast(NormalizedLog.source_ip, String))))
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= (now - timedelta(days=14))
        ).group_by(NormalizedLog.vendor).all()

        # Risk score calculation (simple weighted formula)
        risk_score = AnalyticsService._calculate_risk_score(severity_map, current_events)

        # Top risk factors
        risk_factors = db.query(Alert.alert_type).filter(
            Alert.tenant_id == tenant_id,
            Alert.status == 'open',
            Alert.severity.in_(['critical', 'high'])
        ).distinct().limit(3).all()

        return {
            "total_events": {
                "count": current_events,
                "trend": round(event_trend, 1)
            },
            "active_threats": {
                "count": total_threats,
                "critical": severity_map.get('critical', 0),
                "high": severity_map.get('high', 0),
                "medium": severity_map.get('medium', 0),
                "low": severity_map.get('low', 0)
            },
            "affected_assets": {
                "count": affected_assets,
                "types": {v or "unknown": c for v, c in asset_types}
            },
            "risk_score": {
                "score": risk_score,
                "status": "critical" if risk_score >= 80 else "warning" if risk_score >= 50 else "safe",
                "factors": [f[0] for f in risk_factors]
            }
        }

    @staticmethod
    def _calculate_risk_score(severity_map: Dict[str, int], event_count: int) -> int:
        """Calculate a simple risk score based on alert severity distribution."""
        score = 10  # Baseline

        # Severity weights
        score += severity_map.get('critical', 0) * 20
        score += severity_map.get('high', 0) * 10
        score += severity_map.get('medium', 0) * 5
        score += severity_map.get('low', 0) * 2

        # High event volume adds risk
        if event_count > 10000:
            score += 10
        elif event_count > 5000:
            score += 5

        return min(score, 100)

    @staticmethod
    def get_timeline(
        tenant_id: str,
        db: Session,
        time_range: str = "24h",
        bucket: str = "hour"
    ) -> Dict[str, Any]:
        """
        Get event timeline for charts.
        
        Args:
            tenant_id: Tenant identifier
            db: Database session
            time_range: "24h", "7d", or "30d"
            bucket: "hour" or "day"
        """
        now = datetime.utcnow()
        
        # Parse time range
        range_map = {"24h": 24, "7d": 168, "30d": 720}
        hours = range_map.get(time_range, 24)
        start_time = now - timedelta(hours=hours)

        # Determine bucket format based on DB type
        if db.bind.dialect.name == 'sqlite':
            if bucket == "hour":
                time_bucket = func.strftime('%Y-%m-%d %H:00:00', NormalizedLog.timestamp)
            else:
                time_bucket = func.strftime('%Y-%m-%d', NormalizedLog.timestamp)
        else:
            if bucket == "hour":
                time_bucket = func.date_trunc('hour', NormalizedLog.timestamp)
            else:
                time_bucket = func.date_trunc('day', NormalizedLog.timestamp)

        # Events per bucket
        events_query = db.query(
            time_bucket.label('timestamp'),
            func.count(NormalizedLog.id).label('events')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= start_time
        ).group_by('timestamp').order_by('timestamp').all()

        # Threats per bucket (high severity logs)
        threats_query = db.query(
            time_bucket.label('timestamp'),
            func.count(NormalizedLog.id).label('threats')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= start_time,
            NormalizedLog.severity.in_(['critical', 'high'])
        ).group_by('timestamp').order_by('timestamp').all()

        # Merge results
        events_map = {str(e.timestamp): e.events for e in events_query}
        threats_map = {str(t.timestamp): t.threats for t in threats_query}

        series = []
        for ts in events_map.keys():
            series.append({
                "timestamp": ts,
                "events": events_map.get(ts, 0),
                "threats": threats_map.get(ts, 0)
            })

        return {
            "range": time_range,
            "bucket": bucket,
            "series": series
        }

    @staticmethod
    def get_threat_vectors(tenant_id: str, db: Session, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threat vectors by alert type."""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_48h = now - timedelta(hours=48)

        # Current period
        current = db.query(
            Alert.alert_type,
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.tenant_id == tenant_id,
            Alert.created_at >= last_24h
        ).group_by(Alert.alert_type, Alert.severity).all()

        # Previous period for trend
        previous = db.query(
            Alert.alert_type,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.tenant_id == tenant_id,
            Alert.created_at >= last_48h,
            Alert.created_at < last_24h
        ).group_by(Alert.alert_type).all()

        prev_map = {p.alert_type: p.count for p in previous}

        result = []
        for row in current:
            prev_count = prev_map.get(row.alert_type, 0)
            trend = 0.0
            if prev_count > 0:
                trend = ((row.count - prev_count) / prev_count) * 100

            result.append({
                "type": row.alert_type,
                "count": row.count,
                "severity": row.severity,
                "trend": round(trend, 1)
            })

        # Sort by count descending
        result.sort(key=lambda x: x['count'], reverse=True)
        return result[:limit]

    @staticmethod
    def get_geo_distribution(tenant_id: str, db: Session) -> List[Dict[str, Any]]:
        """Get geographic distribution of events."""
        # This queries the business_context JSON field for geoip data
        # For SQLite, we use json_extract
        if db.bind.dialect.name == 'sqlite':
            country = func.json_extract(NormalizedLog.business_context, '$.geoip.country')
            country_code = func.json_extract(NormalizedLog.business_context, '$.geoip.code')
        else:
            country = NormalizedLog.business_context['geoip']['country'].astext
            country_code = NormalizedLog.business_context['geoip']['code'].astext

        results = db.query(
            country.label('country_name'),
            country_code.label('country_code'),
            func.count(NormalizedLog.id).label('event_count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.business_context.isnot(None)
        ).group_by('country_name', 'country_code').order_by(desc('event_count')).limit(20).all()

        # Count high-severity as threats
        threat_query = db.query(
            country.label('country_name'),
            func.count(NormalizedLog.id).label('threat_count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.severity.in_(['critical', 'high']),
            NormalizedLog.business_context.isnot(None)
        ).group_by('country_name').all()

        threat_map = {t.country_name: t.threat_count for t in threat_query}

        return [
            {
                "country_code": r.country_code or "XX",
                "country_name": r.country_name or "Unknown",
                "event_count": r.event_count,
                "threat_count": threat_map.get(r.country_name, 0)
            }
            for r in results
        ]

    @staticmethod
    def get_traffic_analysis(tenant_id: str, db: Session) -> List[Dict[str, Any]]:
        """Get network traffic analysis by protocol."""
        results = db.query(
            NormalizedLog.protocol,
            func.count(NormalizedLog.id).label('connection_count')
        ).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.protocol.isnot(None)
        ).group_by(NormalizedLog.protocol).order_by(desc('connection_count')).all()

        return [
            {
                "protocol": r.protocol or "unknown",
                "connection_count": r.connection_count,
                # Mock bytes for V1 (not tracked in current schema)
                "bytes_in": r.connection_count * 1024,
                "bytes_out": r.connection_count * 512
            }
            for r in results
        ]

    @staticmethod
    def get_business_insights(tenant_id: str, db: Session) -> Dict[str, Any]:
        """Get insights on business activity patterns (last 7 days)."""
        now = datetime.utcnow()
        last_7d = now - timedelta(days=7)
        
        # Query logs for the last 7 days
        logs = db.query(NormalizedLog.timestamp, NormalizedLog.vendor).filter(
            NormalizedLog.tenant_id == tenant_id,
            NormalizedLog.timestamp >= last_7d
        ).all()
        
        business_hours = 0
        after_hours = 0
        weekdays = 0
        weekends = 0
        by_vendor = {}
        
        for log_ts, vendor in logs:
            # Business hours: 09:00 - 17:00
            hour = log_ts.hour
            if 9 <= hour < 18:  # Extended to 18:00 for common business day
                business_hours += 1
            else:
                after_hours += 1
            
            # Weekdays: 0 (Mon) - 4 (Fri)
            day = log_ts.weekday()
            if day < 5:
                weekdays += 1
            else:
                weekends += 1
                
            vendor_name = vendor or "Unknown"
            by_vendor[vendor_name] = by_vendor.get(vendor_name, 0) + 1
            
        return {
            "business_hours": business_hours,
            "after_hours": after_hours,
            "weekdays": weekdays,
            "weekends": weekends,
            "by_vendor": by_vendor
        }
