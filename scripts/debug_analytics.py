
import os
import sys
from datetime import datetime, timedelta
import logging

# Set project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.core.database import db_manager
from src.services.analytics import AnalyticsService
from src.models.database import NormalizedLog, Alert

logging.basicConfig(level=logging.INFO)

def debug_summary():
    # Force SQLite
    database_path = os.path.join(project_root, 'siem_analyzer.db')
    os.environ['DATABASE_URL'] = f"sqlite:///{database_path}"
    
    db_manager.initialize()
    
    tenant_id = 'my_company'
    print(f"DEBUG: Testing summary for tenant: {tenant_id}")
    
    with db_manager.session_scope() as db:
        try:
            summary = AnalyticsService.get_dashboard_summary(tenant_id, db)
            print("SUMMARY RESULT:")
            import json
            print(json.dumps(summary, indent=2))
        except Exception as e:
            import traceback
            print("ERROR IN GET_DASHBOARD_SUMMARY:")
            traceback.print_exc()

if __name__ == "__main__":
    debug_summary()
