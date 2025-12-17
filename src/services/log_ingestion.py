"""Log ingestion service."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert
from src.services.log_adapter import LogAdapter
from src.analyzers.base import analyzer_manager
from src.services.email_alert import EmailAlertService
from src.core.config import config

logger = logging.getLogger(__name__)

class LogIngestionService:
    """Service to ingest, normalize, store, and analyze logs."""

    def __init__(self):
        """Initialize log ingestion service."""
        self.email_service = EmailAlertService()

    def process_log(self, raw_log_data: Dict[str, Any]) -> bool:
        """
        Process a single raw log entry.

        Args:
            raw_log_data: Raw dictionary from Redis or other source.

        Returns:
            True if processed successfully, False otherwise.
        """
        try:
            # 1. Normalize
            normalized_schema = LogAdapter.normalize(raw_log_data)

            # 2. Store to Database
            log_entry = self._store_log(normalized_schema)
            if not log_entry:
                return False

            # 3. Analyze
            # log_entry is detached but should have attributes loaded due to expire_on_commit=False
            alerts = analyzer_manager.analyze_log(log_entry)

            # 4. Handle Alerts
            if alerts:
                self._handle_alerts(alerts)

            return True

        except Exception as e:
            logger.error(f"Error processing log: {e}", exc_info=True)
            return False

    def _store_log(self, schema) -> Optional[NormalizedLog]:
        """Store normalized log to database."""
        session = None
        try:
            # Manually manage session to set expire_on_commit=False
            # This ensures attributes are accessible after commit/close
            session = db_manager.get_session()
            session.expire_on_commit = False

            log_entry = NormalizedLog(
                tenant_id=schema.tenant_id,
                timestamp=schema.timestamp,
                source_ip=schema.source_ip,
                destination_ip=schema.destination_ip,
                source_port=schema.source_port,
                destination_port=schema.destination_port,
                protocol=schema.protocol,
                action=schema.action,
                log_type=schema.log_type,
                message=schema.message,
                raw_data=schema.raw_data
            )
            session.add(log_entry)
            session.commit()

            # No need to refresh explicitly if expire_on_commit=False,
            # but we need the ID populated.
            # Commit should populate the ID.

            return log_entry
        except Exception as e:
            if session:
                session.rollback()
            logger.error(f"Failed to store log: {e}")
            return None
        finally:
            if session:
                session.close()

    def _handle_alerts(self, alerts: list[Alert]):
        """Handle generated alerts (deduplication, notification)."""
        for alert in alerts:
            if alert.severity in ['high', 'critical']:
                logger.info(f"Triggering notification for {alert.severity} alert: {alert.alert_type}")
                self.email_service.send_alert(alert)
