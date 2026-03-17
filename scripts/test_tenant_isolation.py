# #     import json
# import os
# import time
# from datetime import datetime

import requests
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

#from src.models.database import Base, NormalizedLog

# Configuration
BASE_URL = "http://localhost:8000"
DB_URL = "postgresql://siem_user:siem_secure_password_2026@localhost:5433/siem_db"
RLS_TEST_DB_URL = "postgresql://tenant_test_user:test_pass@localhost:5433/siem_db"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "SecurePass123!"

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def setup_database():
    engine = create_engine(DB_URL)
    return engine


def test_database_rls():
    print(f"\n {BOLD}1. Database-Level RLS (PostgreSQL){RESET}")
    engine = setup_database()
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # Clear existing test data
        session.execute(text("DELETE FROM logs WHERE tenant_id IN ('tenant_a', 'tenant_b')"))
        session.commit()

        # Insert test data using raw SQL to avoid INET/VARCHAR mismatch
        session.execute(
            text(
                "INSERT INTO logs (tenant_id, message, timestamp, severity) \
                VALUES ('tenant_a', 'Private Log A', NOW(), 'high')"
            )
        )
        session.execute(
            text(
                "INSERT INTO logs (tenant_id, message, timestamp, severity) \
                VALUES ('tenant_b', 'Private Log B', NOW(), 'low')"
            )
        )
        session.commit()
        print(f"   {GREEN}[INFO]{RESET} Sample logs inserted for 'tenant_a' \
                    and 'tenant_b'")

        rls_engine = create_engine(RLS_TEST_DB_URL)
        with rls_engine.connect() as conn:
            # Scenario 1: Access as tenant_a
            with conn.begin():
                conn.execute(text("SET app.current_tenant = 'tenant_a'"))
                result = conn.execute(text("SELECT message FROM logs")).fetchall()
                messages = [r[0] for r in result if r[0] in ["Private Log A", "Private Log B"]]
                print(f"    {GREEN}[INFO]{RESET} Records visible for 'tenant_a': {messages}")

                if "Private Log B" in messages:
                    print(f"    {RED}[FAIL]{RESET} RLS Leak: tenant_a saw tenant_b logs!")
                else:
                    print(f"    {GREEN}[PASS]{RESET} RLS enforced: tenant_a only saw its own logs.")

            # Scenario 2: Access as tenant_b
            with conn.begin():
                conn.execute(text("SET app.current_tenant = 'tenant_b'"))
                result = conn.execute(text("SELECT message FROM logs")).fetchall()
                messages = [r[0] for r in result if r[0] in ["Private Log A", "Private Log B"]]
                print(f"    {GREEN}[INFO]{RESET} Records visible for 'tenant_b': {messages}")

                if "Private Log A" in messages:
                    print(f"    {RED}[FAIL]{RESET} RLS Leak: tenant_b saw tenant_a logs!")
                else:
                    print(f"    {GREEN}[PASS]{RESET} RLS enforced: tenant_b only saw its own logs.")

    except Exception as e:
        print(f"   {RED}[ERROR]{RESET} DB test failed: {e}")
        import traceback

        traceback.print_exc()
    finally:
        # Cleanup
        try:
            session.execute(text("DELETE FROM logs WHERE tenant_id IN ('tenant_a', 'tenant_b')"))
            session.commit()
        except:
            pass
        session.close()


def test_api_isolation():
    print(f"\n {BOLD}2. Application-Level API Isolation{RESET}")

    # Login as Superadmin to get a token
    login_data = {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    resp = requests.post(f"{BASE_URL}/api/admin/proxy/login", json=login_data)
    if resp.status_code != 200:
        print(f"   {RED}[ERROR]{RESET} API login failed: {resp.text}")
        return

    token = resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    print(f"   {BOLD}Scenario: Accessing 'default' logs with explicit tenant_id query...{RESET}")
    res_default = requests.get(f"{BASE_URL}/api/v1/logs?tenant_id=default", headers=headers)
    print(
        f"    - Superadmin result for 'default': {res_default.status_code}, count: {len(res_default.json().get('data', []))}"
    )

    print(
        f"    - Superadmin result for 'non_existent': {requests.get(f'{BASE_URL}/api/v1/logs?tenant_id=non_existent', headers=headers).status_code}"
    )


def run_isolation_tests():
    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  Tenant Isolation Verification Audit{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")

    test_database_rls()
    test_api_isolation()

    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  Isolation Audit Complete{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")


if __name__ == "__main__":
    run_isolation_tests()
