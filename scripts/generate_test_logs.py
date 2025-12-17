"""Script to generate test logs and push to Redis."""

import sys
import os
import json
import redis
import time
import logging
from datetime import datetime, timedelta

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.config import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_logs():
    """Generate and push test logs to Redis."""
    try:
        r = redis.Redis(
            host=config.redis_host,
            port=config.redis_port,
            db=config.redis_db,
            password=config.redis_password,
            decode_responses=True
        )

        logger.info(f"Connected to Redis at {config.redis_host}:{config.redis_port}")

        # Test Case 1: Brute Force Attack
        logger.info("Generating Brute Force Attack simulation...")
        attacker_ip = "192.168.1.200"
        target_ip = "10.0.0.50"

        for i in range(10):
            log_entry = {
                'tenant_id': 'default',
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': attacker_ip,
                'destination_ip': target_ip,
                'source_port': 40000 + i,
                'destination_port': 22,
                'protocol': 'TCP',
                'action': 'failed',
                'log_type': 'auth',
                'message': f'SSH authentication failed for user root (Attempt {i+1})'
            }
            r.rpush(config.redis_log_queue, json.dumps(log_entry))
            time.sleep(0.1)

        # Test Case 2: Port Scan
        logger.info("Generating Port Scan simulation...")
        scanner_ip = "192.168.1.201"
        target_ip = "10.0.0.51"

        for port in range(20, 40): # 20 unique ports
            log_entry = {
                'tenant_id': 'default',
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': scanner_ip,
                'destination_ip': target_ip,
                'source_port': 55555,
                'destination_port': port,
                'protocol': 'TCP',
                'action': 'denied',
                'log_type': 'firewall',
                'message': f'Connection denied on port {port}'
            }
            r.rpush(config.redis_log_queue, json.dumps(log_entry))
            time.sleep(0.1)

        logger.info("Logs pushed to Redis successfully.")

    except Exception as e:
        logger.error(f"Failed to generate logs: {e}", exc_info=True)

if __name__ == "__main__":
    generate_logs()
