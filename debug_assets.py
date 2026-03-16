
import sys
import os
from sqlalchemy.orm import Session
from sqlalchemy import func

# Add src to path
sys.path.append(os.getcwd())

from src.core.database import db_manager
from src.services.assets import AssetService
from src.models.database import NormalizedLog

def test_get_assets():
    db_manager.initialize()
    with db_manager.session_scope() as session:
        try:
            print("Testing AssetService.get_assets...")
            result = AssetService.get_assets('nairobi_university', session)
            print("Success!")
            print(f"Found {len(result['data'])} assets.")
        except Exception as e:
            print(f"FAILED: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_get_assets()
