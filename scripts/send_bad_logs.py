#!/usr/bin/env python3
"""
Advanced Threat Emulator - Nairobi University Edition
Designed to test Intelligence_Analyzer detection logic with real-world scenarios.
"""

import requests
import json
import sys
import time
import random
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"  # Unified Analyzer API (Repo 2)
API_KEY = "ak_IptmsWPbdVjI5X9d6WPQkA|V4uJcdw-_3W9078ZAY9ubUZrwjB0JqCNms8vsSbn6K8"
TENANT_ID = "nairobi_university"

# Real-world Log Attack Templates
ATTACK_TEMPLATES = {
    "brute_force": {
        "template": "{timestamp} sshd[{pid}]: Failed password for {user} from {src_ip} port {port} ssh2",
        "device_type": "linux_server",
        "level": "warning",
        "users": ["admin", "root", "ubuntu", "test", "webmaster"],
        "ports": [22, 2222]
    },
    "port_scan": {
        "template": "{timestamp} firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC={src_ip} DST=10.0.0.5 LEN=60 PROTO=TCP SPT={src_port} DPT={dst_port} WINDOW=29200 SYN",
        "device_type": "firewall",
        "level": "warning"
    },
    "malware": {
        "template": "{timestamp} win_defender: Threat Detected! Category: Malware, Name: Cobalt Strike Beacon, Action: Blocked, Source: {src_ip}",
        "device_type": "windows_endpoint",
        "level": "critical"
    },
    "data_exfiltration": {
        "template": "{timestamp} squid[1234]: {src_ip} TCP_MISS/200 85403210 POST http://malicious-cloud-storage.net/upload - DIRECT/1.2.3.4 text/plain",
        "device_type": "proxy_server",
        "level": "error"
    },
    "privilege_escalation": {
        "template": "{timestamp} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow ; pam_unix(sudo:auth): auth failure",
        "device_type": "linux_server",
        "level": "critical",
        "users": ["web_service", "dev_user", "guest"]
    },
    "ddos": {
        "template": "{timestamp} nginx[555]: {src_ip} - - [17/Mar/2026:00:00:01 +0000] \"GET / HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0\" [Rate Limit Exceeded: 503]",
        "device_type": "web_server",
        "level": "warning"
    }
}

def send_attack(attack_type, count, device_ip):
    """Generate and send simulated attack logs"""
    if attack_type not in ATTACK_TEMPLATES:
        print(f"Unknown attack type: {attack_type}")
        print(f"Available: {', '.join(ATTACK_TEMPLATES.keys())}")
        return

    config = ATTACK_TEMPLATES[attack_type]
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
        "X-Forwarded-For": device_ip
    }

    print(f"🚀 Launching {attack_type} simulation ({count} logs) from {device_ip}...")
    
    success = 0
    for i in range(count):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        
        # Scenario Logic
        if attack_type == "brute_force":
            msg = config["template"].format(
                timestamp=timestamp,
                pid=random.randint(1000, 9999),
                user=random.choice(config["users"]),
                src_ip=device_ip,
                port=random.choice(config["ports"])
            )
        elif attack_type == "port_scan":
            # Increment port to trigger PortScanAnalyzer threshold
            msg = config["template"].format(
                timestamp=timestamp,
                src_ip=device_ip,
                src_port=random.randint(1024, 65535),
                dst_port=10 + i # Scanning sequential ports
            )
        elif attack_type == "privilege_escalation":
            msg = config["template"].format(
                timestamp=timestamp,
                user=random.choice(config["users"]),
                src_ip=device_ip
            )
        else:
            msg = config["template"].format(
                timestamp=timestamp,
                src_ip=device_ip
            )

        payload = {
            "raw_log": msg,
            "metadata": {
                "tenant_id": TENANT_ID,
                "device_type": config["device_type"],
                "source": "simulation_engine"
            }
        }

        try:
            # Note: We send to Repo 2's direct ingest port if possible, 
            # but usually Repo 1 handles the first layer.
            # Using 8000 for Intelligence_Analyzer (Repo 2) direct API
            resp = requests.post(f"{BASE_URL}/api/v1/logs/ingest", headers=headers, json=payload, timeout=5)
            if resp.status_code == 202:
                success += 1
                print(f" [+] Log {i+1} accepted")
            else:
                print(f" [!] Failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f" [!] Error: {e}")
        
        # High speed for DDoS, moderate for others
        if attack_type != "ddos":
            time.sleep(0.1)

    print(f"\n✅ Simulation Complete: {success}/{count} logs injected.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python send_bad_logs.py [type] [count] [source_ip]")
        print("Types: brute_force, port_scan, malware, data_exfiltration, privilege_escalation, ddos")
        sys.exit(1)

    attack = sys.argv[1]
    qty = int(sys.argv[2])
    ip = sys.argv[3]
    
    send_attack(attack, qty, ip)
