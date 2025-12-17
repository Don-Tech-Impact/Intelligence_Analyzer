"""Migration script to normalize existing logs."""

import sys
import os
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.database import db_manager
from src.models.database import NormalizedLog
from src.services.log_adapter import LogAdapter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_logs():
    """Migrate existing logs to normalized format."""
    logger.info("Starting log migration...")

    try:
        db_manager.initialize()

        with db_manager.session_scope() as session:
            # Fetch logs that might need normalization
            # Assumption: If source_ip is NULL but raw_data is not NULL, it needs processing.
            logs_to_process = session.query(NormalizedLog).filter(
                NormalizedLog.source_ip == None,
                NormalizedLog.raw_data != None
            ).all()

            count = 0
            for log in logs_to_process:
                if not log.raw_data:
                    continue

                # Normalize using adapter
                # Note: raw_data is stored as JSON (dict) in DB
                normalized_schema = LogAdapter.normalize(log.raw_data)

                # Update fields
                log.tenant_id = normalized_schema.tenant_id
                # timestamp might be preserved from original creation if available
                if not log.timestamp and normalized_schema.timestamp:
                    log.timestamp = normalized_schema.timestamp

                log.source_ip = normalized_schema.source_ip
                log.destination_ip = normalized_schema.destination_ip
                log.source_port = normalized_schema.source_port
                log.destination_port = normalized_schema.destination_port
                log.protocol = normalized_schema.protocol
                log.action = normalized_schema.action
                log.log_type = normalized_schema.log_type
                log.message = normalized_schema.message

                count += 1

                if count % 100 == 0:
                    logger.info(f"Processed {count} logs...")

            session.commit()
            logger.info(f"Migration complete. Processed {count} logs.")

    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)

if __name__ == "__main__":
    migrate_logs()
