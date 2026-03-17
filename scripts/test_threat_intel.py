import json
import time

import redis
import requests
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Configuration
REDIS_URL = "redis://localhost:6380/0"  # Finance Redis is 6380, but afric-analyzer-redis-local is 6379?
# Wait, let me check docker ps again.
# afric-analyzer-redis-local: 0.0.0.0:6379->6379/tcp
# I should use 6379.
REDIS_URL = "redis://localhost:6379/0"
DB_URL = "postgresql://siem_user:siem_secure_password_2026@localhost:5433/siem_db"
BASE_URL = "http://localhost:8000"

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
CYAN = "\033[96m"
RESET = "\033[0m"

MALICIOUS_IP = f"1.2.3.{int(time.time()) % 255}"


def setup_threat_intel():
    print(f" {BOLD}Setting up Threat Intel IoC for {MALICIOUS_IP}...{RESET}")
    engine = create_engine(DB_URL)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        # Insert malicious IP
        session.execute(
            text(
                f"""
            INSERT INTO threat_intelligence (indicator_type, indicator_value, \
            threat_type, confidence, source, description) 
            VALUES ('ip', '{MALICIOUS_IP}', 'Botnet C2', 0.95, 'AbuseIPDB', \
            'Known malicious botnet node')
        """
            )
        )
        session.commit()
        print(f"  {GREEN}[SUCCESS]{RESET} IP {MALICIOUS_IP} registered as malicious C2.")
    except Exception as e:
        print(f"  {RED}[ERROR]{RESET} Failed to setup IoC: {e}")
    finally:
        session.close()


def inject_log():
    print(f" {BOLD}Injecting log with malicious IP {MALICIOUS_IP}...{RESET}")
    r = redis.from_url(REDIS_URL)
    log_data = {
        "tenant_id": "default",
        "vendor": "Forcepoint",
        "log_type": "firewall",
        "source_ip": MALICIOUS_IP,
        "destination_ip": "10.0.0.5",
        "action": "allow",
        "message": f"Outbound connection to known C2 {MALICIOUS_IP}",
    }
    r.rpush("log_queue", json.dumps(log_data))
    print(f"  {GREEN}[SUCCESS]{RESET} Log pushed to Redis queue 'log_queue'.")


def verify_alert():
    print(f" {BOLD}Waiting for alert generation...{RESET}")
    # Give the worker a few seconds
    time.sleep(5)

    # We'll use the API to check for alerts
    # Need admin token
    login_data = {"email": "admin@example.com", "password": "SecurePass123!"}
    resp = requests.post(f"{BASE_URL}/api/admin/proxy/login", json=login_data)
    token = resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    attempts = 0
    while attempts < 3:
        resp = requests.get(f"{BASE_URL}/api/v1/alerts?alert_type=threat_intel", headers=headers)
        alerts = resp.json().get("data", [])

        for alert in alerts:
            if alert.get("source_ip") == MALICIOUS_IP:
                print(f"  {GREEN}[PASS]{RESET} Alert found! Severity: {alert.get('severity')}")
                print(f"    - Description: {alert.get('description')}")
                return True

        print(f"  - Attempt {attempts+1}: Alert not found yet, retrying...")
        time.sleep(3)
        attempts += 1

    print(f"  {RED}[FAIL]{RESET} No threat_intel alert found for {MALICIOUS_IP}")
    return False


if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  Threat Intelligence Worker Audit{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")

    setup_threat_intel()
    inject_log()
    verify_alert()

    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
