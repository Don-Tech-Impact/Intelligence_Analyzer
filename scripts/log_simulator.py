import json
import time
import random
import uuid
import sys
import redis
from datetime import datetime, timedelta

# Configuration
REDIS_URL = "redis://localhost:6379/0"
TENANT_ID = "Nairobi"
INGEST_QUEUE = f"logs:{TENANT_ID}:ingest"

# Device Profiles
DEVICES = [
    {"hostname": "NRB-FW-01", "ip": "10.0.1.1", "vendor": "fortinet", "type": "fortigate"},
    {"hostname": "NRB-SRV-WEB", "ip": "10.0.1.10", "vendor": "generic", "type": "generic_syslog"},
    {"hostname": "NRB-SRV-DB", "ip": "10.0.1.20", "vendor": "generic", "type": "generic_syslog"},
    {"hostname": "NRB-VPN-GW", "ip": "10.0.1.5", "vendor": "cisco", "type": "cisco_asa"},
    {"hostname": "NRB-USER-PC", "ip": "10.0.1.100", "vendor": "generic", "type": "generic_syslog"},
]

# Attack Patterns
ATTACK_IPS = ["192.168.50.1", "45.33.22.11", "91.22.33.44", "203.0.113.5", "185.199.108.153"]

def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)

def send_log(r, log_data):
    r.lpush(INGEST_QUEUE, json.dumps(log_data))

def generate_v1_log(device, message, level="info", source_ip=None):
    return {
        "schema_version": "v1",
        "log_id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "raw_log": message,
        "timestamp": datetime.utcnow().isoformat(),
        "level": level,
        "metadata": {
            "device_type": device["type"],
            "source_ip": source_ip or device["ip"],
            "device_hostname": device["hostname"],
            "vendor": device["vendor"]
        }
    }

def stage_1_basic(r):
    print("Running Stage 1: Basic logs...")
    for _ in range(10):
        device = random.choice(DEVICES[:2])
        msg = f"Normal operational log from {device['hostname']}"
        log = generate_v1_log(device, msg)
        send_log(r, log)
        print(f" Sent log from {device['hostname']}")
        time.sleep(1)

def stage_2_business(r):
    print("Running Stage 2: Massive business day logs...")
    for i in range(100):
        device = random.choice(DEVICES[:4])
        msg = f"User session active: {device['hostname']}. Data transfer of {random.randint(10, 5000)} bytes."
        log = generate_v1_log(device, msg)
        send_log(r, log)
        if i % 10 == 0:
            print(f" Sent {i} logs...")
        time.sleep(0.1)
    print("Stage 2 Complete.")

def stage_3_attack(r):
    print("Running Stage 3: Massive attack logs...")
    # 1. Brute Force Simulation
    attacker_ip = ATTACK_IPS[0]
    target_device = DEVICES[3] # VPN GW
    print(f"Simulating Brute Force on {target_device['hostname']} from {attacker_ip}...")
    for _ in range(20):
        msg = f"%ASA-6-605005: Login permitted from {attacker_ip} for user 'admin' on interface outside"
        # Wait, if I want to trigger brute force analyzer, I should send failures.
        msg = f"%ASA-6-605004: Login denied from {attacker_ip} for user 'admin' on interface outside"
        log = generate_v1_log(target_device, msg, level="warning", source_ip=attacker_ip)
        send_log(r, log)
        time.sleep(0.05)

    # 2. Port Scan Simulation
    attacker_ip_2 = ATTACK_IPS[1]
    target_srv = DEVICES[1] # WEB SRV
    print(f"Simulating Port Scan on {target_srv['hostname']} from {attacker_ip_2}...")
    for port in range(20, 100):
        msg = f"Connection attempt from {attacker_ip_2} to {target_srv['ip']}:{port} blocked by policy"
        log = generate_v1_log(target_srv, msg, level="warning", source_ip=attacker_ip_2)
        send_log(r, log)
        time.sleep(0.02)

    # 3. Massive background traffic
    for i in range(300):
        device = random.choice(DEVICES)
        msg = f"Traffic spike observed on {device['hostname']}"
        log = generate_v1_log(device, msg)
        send_log(r, log)
        if i % 50 == 0:
            print(f" Sent {i+100} logs...")
        time.sleep(0.01)
    print("Stage 3 Complete.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python log_simulator.py <stage1|stage2|stage3>")
        sys.exit(1)

    stage = sys.argv[1]
    r = get_redis()
    
    if stage == "stage1":
        stage_1_basic(r)
    elif stage == "stage2":
        stage_2_business(r)
    elif stage == "stage3":
        stage_3_attack(r)
    else:
        print("Invalid stage")
