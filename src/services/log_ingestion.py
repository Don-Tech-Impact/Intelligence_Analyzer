"""Log ingestion service."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert
from src.services.log_adapter import LogAdapter
# Import analyzers package to auto-register all analyzers
from src import analyzers
from src.analyzers.base import analyzer_manager
from src.services.notification_manager import notification_manager
from src.core.config import config

from src.services.enrichment import EnrichmentService

logger = logging.getLogger(__name__)

class AnalysisPipeline:
    """Service to process standardized logs: enrich, store, and analyze."""

    def __init__(self):
        """Initialize analysis pipeline."""
        pass

    def process_log(self, raw_log_data: Dict[str, Any]) -> bool:
        """
        Process a pre-normalized log entry.

        Args:
            raw_log_data: Standardized JSON from Repo 1.

        Returns:
            True if processed successfully, False otherwise.
        """
        try:
            # 1. Validate against Schema (using refactored LogAdapter)
            normalized_schema = LogAdapter.normalize(raw_log_data)

            # 2. Store to Database
            log_entry = self._store_log(normalized_schema)
            if not log_entry:
                return False

            # 3. Enrich with Intelligence (GeoIP, Threat Intel, Scoring)
            EnrichmentService.enrich(log_entry)
            
            # Save enrichment results
            with db_manager.session_scope() as session:
                session.add(log_entry)
                session.commit()

            # 4. Perform Threat Analysis (Brute Force, Port Scan, etc.)
            alerts = analyzer_manager.analyze_log(log_entry)

            # 5. Handle Alerts (Notifications)
            if alerts:
                self._handle_alerts(alerts)

            return True

        except Exception as e:
            logger.error(f"Error in analysis pipeline: {e}", exc_info=True)
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
                company_id=schema.company_id,
                tenant_id=schema.tenant_id,
                device_id=schema.device_id,
                timestamp=schema.timestamp,
                source_ip=schema.source_ip,
                destination_ip=schema.destination_ip,
                source_port=schema.source_port,
                destination_port=schema.destination_port,
                protocol=schema.protocol,
                action=schema.action,
                vendor=schema.vendor,
                device_hostname=schema.device_hostname,
                severity=schema.severity,
                message=schema.message,
                raw_data=schema.raw_data,
                business_context=schema.business_context
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
            notification_manager.notify(alert)

