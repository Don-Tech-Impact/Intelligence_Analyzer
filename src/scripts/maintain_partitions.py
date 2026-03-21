#!/usr/bin/env python3
"""
Log Partition Maintenance Script for Intelligence Analyzer.
Usage: python scripts/maintain_partitions.py --months-ahead 6 --retention-months 12
"""

import argparse
import logging
import sys
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
from sqlalchemy import text

# Add project root to path for imports
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.database import db_manager
from src.core.config import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PartitionManager")

def maintain_partitions(months_ahead: int = 6, retention_months: int = 12):
    """
    1. Pre-creates partitions for the next N months.
    2. Drops partitions older than M months.
    """
    db_manager.initialize()
    
    with db_manager.session_scope() as session:
        # --- 1. PRE-CREATE FUTURE PARTITIONS ---
        current_date = date.today().replace(day=1)
        for i in range(months_ahead + 1):
            target_month = current_date + relativedelta(months=i)
            month_str = target_month.strftime('%Y-%m')
            
            logger.info(f"Ensuring partition for {month_str}...")
            try:
                # Calls the stored procedure defined in init_db.sql
                session.execute(text("SELECT create_logs_partition(:month)"), {"month": month_str})
            except Exception as e:
                logger.error(f"Failed to create partition for {month_str}: {e}")

        # --- 2. ENFORCE RETENTION POLICY ---
        if retention_months > 0:
            cutoff_date = current_date - relativedelta(months=retention_months)
            logger.info(f"Enforcing retention policy: Dropping partitions older than {cutoff_date.strftime('%Y-%m')}")
            
            # Query existing partitions
            try:
                result = session.execute(text(
                    "SELECT relname FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'public' AND relname LIKE 'logs_%' "
                    "AND relname != 'logs_default' AND relkind = 'r'"
                ))
                
                partitions = [row[0] for row in result]
                for p_name in partitions:
                    try:
                        # Extract date from logs_YYYY_MM
                        p_date_str = p_name.replace('logs_', '').replace('_', '-') + '-01'
                        p_date = datetime.strptime(p_date_str, '%Y-%m-%d').date()
                        
                        if p_date < cutoff_date:
                            logger.warning(f"Dropping expired partition: {p_name}")
                            session.execute(text(f"DROP TABLE IF EXISTS {p_name}"))
                    except ValueError:
                        continue # Skip tables that don't match the YYYY_MM pattern
            except Exception as e:
                logger.error(f"Failed to enforce retention policy: {e}")

    db_manager.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Maintain SIEM log partitions")
    parser.add_argument("--months-ahead", type=int, default=6, help="How many future partitions to ensure")
    parser.add_argument("--retention-months", type=int, default=12, help="How many months of logs to keep")
    
    args = parser.parse_args()
    maintain_partitions(args.months_ahead, args.retention_months)
