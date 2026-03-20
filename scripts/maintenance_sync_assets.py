"""Maintenance script to sync managed devices from SIEM to Repo 1 allowlist.

Usage:
    python scripts/maintenance_sync_assets.py
"""

import os
import sys
import logging
import requests
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from src.models.database import ManagedDevice
from src.core.config import config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AssetSync")

def sync_assets():
    """Fetches all managed devices and pushes them to Repo 1."""
    # 1. Config
    db_url = config.database_url
    repo1_url = (os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080").rstrip('/')
    admin_key = os.getenv("ADMIN_KEY") or os.getenv("ADMIN_API_KEY") or "changeme-admin-key"
    
    logger.info(f"Target Repo 1: {repo1_url}")
    logger.info(f"Syncing from: {db_url}")

    # 2. Database Connection
    try:
        engine = create_engine(db_url)
        session = Session(engine)
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        return

    # 3. Fetch Devices
    try:
        devices = session.query(ManagedDevice).all()
        logger.info(f"Found {len(devices)} managed devices in SIEM database.")
    except Exception as e:
        logger.error(f"Failed to query managed_devices: {e}")
        session.close()
        return

    print(devices[3].to_dict())  

    # # 4. Sync Loop
    # success_count = 0
    # fail_count = 0
    
    # headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}
    
    # for device in devices:
    #     tenant_id = device.tenant_id
    #     ip = device.ip_address
    #     name = device.name
        
    #     logger.info(f"Syncing [{tenant_id}] {name} ({ip})...")
        
    #     payload = {
    #         "ip_range": ip,
    #         "description": f"SIEM Managed: {name}",
    #         "label": f"SIEM Managed: {name}", # Compatibility
    #         "is_active": True
    #     }
        
    #     try:
    #         # Endpoint verified in previous turn: POST /admin/tenants/{tid}/ips
    #         url = f"{repo1_url}/admin/tenants/{tenant_id}/ips"
    #         res = requests.post(url, json=payload, headers=headers, timeout=5.0)
            
    #         if res.status_code in (200, 201):
    #             logger.info(f"  [PASS] Successfully synced {ip}")
    #             success_count += 1
    #         elif res.status_code == 409:
    #             logger.info(f"  [SKIP] {ip} already exists in Repo 1")
    #             success_count += 1
    #         else:
    #             logger.error(f"  [FAIL] Repo 1 returned {res.status_code}: {res.text}")
    #             fail_count += 1
                
    #     except Exception as e:
    #         logger.error(f"  [ERROR] Connection failed for {ip}: {e}")
    #         fail_count += 1

    # 5. Summary
    logger.info("=" * 40)
    logger.info("SYNC SUMMARY")
    logger.info("=" * 40)
    logger.info(f"Total Devices: {len(devices)}")
    # logger.info(f"Successful/Skipped: {success_count}")
    # logger.info(f"Failed: {fail_count}")
    logger.info("=" * 40)
    
    session.close()

if __name__ == "__main__":
    sync_assets()
