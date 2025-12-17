"""Script to create Grafana friendly views."""

import sys
import os
import logging
from sqlalchemy import text

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.database import db_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_views():
    """Create SQL views for Grafana."""
    logger.info("Creating Grafana views...")

    try:
        db_manager.initialize()

        with db_manager.session_scope() as session:
            # View 1: Logs View (Simplified selection)
            # Since we have normalized columns in the table, a view might just select them
            # making it easier for Grafana to see a "flat" table.
            logger.info("Creating view: logs_view")
            session.execute(text("""
                CREATE VIEW IF NOT EXISTS logs_view AS
                SELECT
                    id,
                    tenant_id,
                    timestamp,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    protocol,
                    action,
                    log_type,
                    message
                FROM logs;
            """))

            # View 2: Alerts View
            logger.info("Creating view: alerts_view")
            session.execute(text("""
                CREATE VIEW IF NOT EXISTS alerts_view AS
                SELECT
                    id,
                    tenant_id,
                    created_at,
                    alert_type,
                    severity,
                    source_ip,
                    destination_ip,
                    description,
                    status
                FROM alerts;
            """))

            # View 3: Attacks Summary (Aggregation)
            # Useful for "Attacks over time" or "Top Attackers"
            # Note: SQLite syntax limitations apply, but basic aggregation is fine.
            logger.info("Creating view: attacks_summary_view")
            session.execute(text("""
                CREATE VIEW IF NOT EXISTS attacks_summary_view AS
                SELECT
                    date(created_at) as attack_date,
                    alert_type,
                    severity,
                    count(*) as attack_count
                FROM alerts
                GROUP BY date(created_at), alert_type, severity;
            """))

            logger.info("Views created successfully.")

    except Exception as e:
        logger.error(f"Failed to create views: {e}", exc_info=True)

if __name__ == "__main__":
    create_views()
