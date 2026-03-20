import os
import requests
import logging
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from src.models.database import Tenant, User
from src.core.config import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Bootstrap")

def bootstrap():
    repo1_url = (os.getenv("REPO1_BASE_URL") or "http://host.docker.internal:8080").rstrip('/')
    admin_key = os.getenv("ADMIN_KEY") or "changeme-admin-key"
    headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}

    # 1. Create Superadmin in Repo 1 (via Proxy or direct if possible)
    # We will try to use the Repo 2 proxy to reach Repo 1
    logger.info("Initializing Superadmin in Repo 1...")
    user_payload = {
        "username": "admin",
        "email": "admin@example.com",
        "password": "SecurePass123!", # Update this as needed
        "role": "superadmin",
        "is_active": True
    }
    
    try:
        # We call Repo 1's user creation endpoint directly using the Admin Key
        res = requests.post(f"{repo1_url}/admin/users", json=user_payload, headers=headers, timeout=5)
        if res.status_code in (200, 201, 409):
            logger.info("  [PASS] Superadmin 'admin@example.com' is ready in Repo 1.")
        else:
            logger.error(f"  [FAIL] Could not create user in Repo 1: {res.status_code} - {res.text}")
    except Exception as e:
        logger.error(f"  [ERROR] Connection to Repo 1 failed: {e}")

    # 2. Initialize Tenant in Repo 2 (SIEM)
    logger.info("Initializing Local Tenant record in SIEM...")
    engine = create_engine(config.database_url)
    with Session(engine) as session:
        t = session.query(Tenant).filter(Tenant.tenant_id == "nairobi_university").first()
        if not t:
            t = Tenant(tenant_id="nairobi_university", name="Nairobi University", is_active=True)
            session.add(t)
            session.commit()
            logger.info("  [PASS] Tenant 'nairobi_university' initialized in SIEM database.")
        else:
            logger.info("  [SKIP] Tenant 'nairobi_university' already exists.")

    logger.info("Bootstrap Complete! You can now login with admin@example.com")

if __name__ == "__main__":
    bootstrap()
