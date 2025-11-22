#!/usr/bin/env python3
"""
Replay logs and emit test brute-force alerts whenever a log’s threat_intel.indicators
contains anything (e.g., 'remote_access_attempt').
"""

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func, text

from src.core.database import db_manager
from src.models.database import Log as DBLog, Alert as DBAlert
from src.analyzers.brute_force import BruteForceAnalyzer
from src.analyzers.base import analyzer_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("replay_bruteforce")

FAILED_RE = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")


def _extract_source_ip(db_log: DBLog) -> Optional[str]:
    """Try structured source JSON, fall back to regex in raw_message."""
    src = db_log.source or {}
    ip = src.get("ip")
    if ip:
        return ip
    if db_log.raw_message:
        match = FAILED_RE.search(db_log.raw_message)
        if match:
            return match.group("ip")
    return None


def replay_all(tenant: Optional[str] = None, indicator_filter: Optional[str] = None):
    logger.info("Initializing DB engine and tables")
    db_manager.initialize()

    analyzer_manager.analyzers.clear()
    analyzer_manager.register(BruteForceAnalyzer())

    # Load candidate logs while session open
    with db_manager.session_scope() as session:
        q = session.query(DBLog).order_by(DBLog.event_time)
        if tenant:
            q = q.filter(DBLog.tenant_id == tenant)
        if indicator_filter:
            # SQLite JSON filter: look for substring inside threat_intel JSON
            pattern = f"%{indicator_filter}%"
            q = q.filter(text("COALESCE(threat_intel, '{}') LIKE :pattern")).params(pattern=pattern)

        db_logs = q.all()
        logger.info("Loaded %d logs (tenant=%s indicator=%s)", len(db_logs), tenant, indicator_filter)

        # Testing-only brute force detection based purely on threat_intel indicators
        temp_counts = defaultdict(list)  # key=(tenant_id, source_ip)
        threshold = 2
        alerts_created = 0

        for log in db_logs:
            indicators = (log.threat_intel or {}).get("indicators") or []
            if not indicators:
                continue
            source_ip = _extract_source_ip(log)
            if not source_ip:
                continue

            ts = log.event_time or log.received_at or datetime.utcnow()
            key = (log.tenant_id, source_ip)
            temp_counts[key].append(ts)

            window_start = ts - timedelta(minutes=5)
            temp_counts[key] = [t for t in temp_counts[key] if t >= window_start]

            attempts = len(temp_counts[key])
            logger.info("IP %s indicator hits=%s (count=%s)", source_ip, indicators, attempts)

            if attempts >= threshold:
                description = (
                    f"Test brute-force (threat intel) from {source_ip}: "
                    f"{attempts} hits in 5 minutes."
                )
                details = {
                    "source_ip": source_ip,
                    "indicator_hits": indicators,
                    "attempts": attempts,
                    "first_seen": min(temp_counts[key]).isoformat(),
                    "last_seen": max(temp_counts[key]).isoformat(),
                }
                exists = session.query(DBAlert.id).filter_by(
                    log_id=log.id, alert_type="brute_force_test"
                ).first()
                if exists:
                    logger.info("Alert already stored for log %s; skipping duplicate", log.id)
                    temp_counts.pop(key, None)
                    continue
                alert = BruteForceAnalyzer().create_alert(
                    alert_type="brute_force_test",
                    severity="medium",
                    # source_ip=source_ip,
                    description=description,
                    details=details,
                    tenant_id=log.tenant_id,
                    log_id=log.id,
                )
                if alert:
                    alerts_created += 1
                    logger.info("Stored test alert id=%s", alert.id)
                temp_counts.pop(key, None)

    logger.info("Replay complete. Test alerts created: %s", alerts_created)
    return alerts_created


if __name__ == "__main__":
    replay_all()