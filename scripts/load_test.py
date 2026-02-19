#!/usr/bin/env python3
"""Load Test Script for Intelligence Analyzer.

=============================================================================
PURPOSE
=============================================================================
Simulates high-volume log ingestion to test system performance.
Pushes logs to Redis queues and monitors:
- Queue depth (should stay < 1000)
- Processing rate
- Memory usage
- Error rate

USAGE:
    python scripts/load_test.py --rate 1000 --duration 60
    
    Options:
        --rate: Logs per second (default: 100)
        --duration: Test duration in seconds (default: 60)
        --queue: Target queue (default: ingest_logs)
        --tenants: Number of tenants to simulate (default: 5)

=============================================================================
"""

import os
import sys
import time
import json
import random
import argparse
import logging
import threading
from datetime import datetime, timedelta
from typing import List, Dict
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# TEST DATA GENERATORS
# =============================================================================

TENANTS = ['acme_corp', 'globex', 'initech', 'umbrella', 'cyberdyne']
LOG_TYPES = ['firewall', 'auth', 'network', 'syslog', 'application']
ACTIONS = ['allow', 'deny', 'accept', 'reject', 'failed', 'success']
SEVERITIES = ['low', 'medium', 'high', 'critical']
VENDORS = ['cisco', 'paloalto', 'fortinet', 'checkpoint', 'linux']

# Sample IPs for realistic traffic patterns
INTERNAL_IPS = ['192.168.1.' + str(i) for i in range(1, 255)]
EXTERNAL_IPS = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9'] + \
               [f"45.33.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)]
MALICIOUS_IPS = ['185.220.101.1', '45.155.205.233', '194.26.29.113']


def generate_ingest_log(tenant_id: str = None, include_attack: bool = False) -> Dict:
    """Generate a realistic ingest log payload (Repo1 format)."""
    tenant = tenant_id or random.choice(TENANTS)
    log_type = random.choice(LOG_TYPES)
    
    # Base log structure (Repo1 format)
    log = {
        "type": "ingest_log",
        "timestamp": datetime.utcnow().isoformat(),
        "source": random.choice(VENDORS),
        "parsed": {
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": random.choice(EXTERNAL_IPS),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([22, 80, 443, 3389, 8080, 25, 53, 8443]),
            "proto": random.choice(['tcp', 'udp', 'icmp']),
            "action": random.choice(ACTIONS),
            "hostname": f"host-{random.randint(1, 100)}.{tenant}.local"
        },
        "metadata": {
            "tenant_id": tenant,
            "device_id": f"fw-{random.randint(1, 10)}",
            "severity": random.choice(SEVERITIES),
            "business_context": {"environment": "production"}
        }
    }
    
    # Inject attack patterns for testing
    if include_attack:
        attack_type = random.choice(['brute_force', 'port_scan', 'c2_beacon'])
        
        if attack_type == 'brute_force':
            log['parsed']['dst_port'] = 22
            log['parsed']['action'] = 'failed'
            log['source'] = 'linux'
        elif attack_type == 'port_scan':
            log['parsed']['dst_port'] = random.randint(1, 65535)
            log['parsed']['action'] = 'deny'
        elif attack_type == 'c2_beacon':
            log['parsed']['src_ip'] = random.choice(INTERNAL_IPS[:5])  # Same internal host
            log['parsed']['dst_ip'] = random.choice(MALICIOUS_IPS)
    
    return log


def generate_clean_log(tenant_id: str = None) -> Dict:
    """Generate a clean (pre-normalized) log payload."""
    tenant = tenant_id or random.choice(TENANTS)
    
    return {
        "type": "clean_log",
        "normalized": {
            "tenant_id": tenant,
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": random.choice(INTERNAL_IPS),
            "destination_ip": random.choice(EXTERNAL_IPS),
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([80, 443]),
            "protocol": "tcp",
            "action": "allow",
            "log_type": "firewall",
            "vendor": "paloalto",
            "severity": "low",
            "message": "Session allowed"
        }
    }


def generate_dead_log() -> Dict:
    """Generate a malformed dead log."""
    return {
        "type": "dead_log",
        "reason": random.choice(['parse_error', 'validation_error', 'unknown_format']),
        "error": "Failed to parse log: unexpected format",
        "raw_log": f"INVALID LOG DATA {random.randint(1000, 9999)}"
    }


# =============================================================================
# LOAD TEST ENGINE
# =============================================================================

class LoadTestEngine:
    """Engine for running load tests against Redis queues."""
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        rate: int = 100,
        duration: int = 60,
        queue: str = "ingest_logs",
        num_tenants: int = 5,
        attack_ratio: float = 0.05
    ):
        self.redis_url = redis_url
        self.rate = rate  # logs per second
        self.duration = duration  # seconds
        self.queue = queue
        self.num_tenants = num_tenants
        self.attack_ratio = attack_ratio
        
        self.redis_client = None
        self.running = False
        
        # Metrics
        self.stats = {
            'sent': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None,
            'queue_depths': [],
            'send_latencies': []
        }
    
    def connect(self):
        """Connect to Redis."""
        self.redis_client = redis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=5
        )
        self.redis_client.ping()
        logger.info(f"Connected to Redis")
    
    def generate_log(self) -> Dict:
        """Generate a log based on queue type and attack probability."""
        include_attack = random.random() < self.attack_ratio
        
        if self.queue == 'ingest_logs':
            return generate_ingest_log(include_attack=include_attack)
        elif self.queue == 'clean_logs':
            return generate_clean_log()
        elif self.queue == 'dead_logs':
            return generate_dead_log()
        else:
            return generate_ingest_log(include_attack=include_attack)
    
    def push_log(self, log: Dict):
        """Push a single log to Redis queue."""
        try:
            self.redis_client.lpush(self.queue, json.dumps(log))
            self.stats['sent'] += 1
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Failed to push log: {e}")
    
    def monitor_queue(self):
        """Background thread to monitor queue depth."""
        while self.running:
            try:
                depth = self.redis_client.llen(self.queue)
                self.stats['queue_depths'].append({
                    'timestamp': time.time(),
                    'depth': depth
                })
                
                # Alert if queue backing up
                if depth > 1000:
                    logger.warning(f"Queue backup detected: {depth} messages")
                
            except Exception as e:
                logger.error(f"Monitor error: {e}")
            
            time.sleep(1)
    
    def run(self):
        """Run the load test."""
        self.connect()
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start monitor thread
        monitor_thread = threading.Thread(target=self.monitor_queue)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        logger.info("="*60)
        logger.info("LOAD TEST STARTED")
        logger.info("="*60)
        logger.info(f"Target queue: {self.queue}")
        logger.info(f"Rate: {self.rate} logs/sec")
        logger.info(f"Duration: {self.duration} seconds")
        logger.info(f"Attack ratio: {self.attack_ratio*100}%")
        logger.info("="*60)
        
        # Calculate timing
        interval = 1.0 / self.rate  # seconds between logs
        end_time = time.time() + self.duration
        
        last_report = time.time()
        batch_start = time.time()
        batch_count = 0
        
        try:
            while time.time() < end_time:
                log = self.generate_log()
                
                send_start = time.time()
                self.push_log(log)
                send_latency = (time.time() - send_start) * 1000
                self.stats['send_latencies'].append(send_latency)
                
                batch_count += 1
                
                # Progress report every 10 seconds
                if time.time() - last_report >= 10:
                    elapsed = time.time() - self.stats['start_time']
                    actual_rate = self.stats['sent'] / elapsed
                    queue_depth = self.redis_client.llen(self.queue)
                    
                    logger.info(
                        f"Progress: {self.stats['sent']} sent | "
                        f"Rate: {actual_rate:.1f}/sec | "
                        f"Queue: {queue_depth} | "
                        f"Errors: {self.stats['errors']}"
                    )
                    last_report = time.time()
                
                # Rate limiting
                elapsed_batch = time.time() - batch_start
                expected_elapsed = batch_count * interval
                sleep_time = expected_elapsed - elapsed_batch
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
                # Reset batch counter periodically
                if batch_count >= self.rate:
                    batch_start = time.time()
                    batch_count = 0
                    
        except KeyboardInterrupt:
            logger.info("Test interrupted by user")
        
        self.running = False
        self.stats['end_time'] = time.time()
        
        self.report()
    
    def report(self):
        """Generate test report."""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        logger.info("="*60)
        logger.info("LOAD TEST RESULTS")
        logger.info("="*60)
        
        # Throughput
        actual_rate = self.stats['sent'] / duration
        logger.info(f"Duration: {duration:.1f} seconds")
        logger.info(f"Total sent: {self.stats['sent']}")
        logger.info(f"Total errors: {self.stats['errors']}")
        logger.info(f"Actual rate: {actual_rate:.1f} logs/sec")
        logger.info(f"Target rate: {self.rate} logs/sec")
        logger.info(f"Efficiency: {(actual_rate/self.rate)*100:.1f}%")
        
        # Latency
        if self.stats['send_latencies']:
            import statistics
            latencies = self.stats['send_latencies']
            logger.info(f"Send latency (p50): {statistics.median(latencies):.2f}ms")
            logger.info(f"Send latency (p95): {sorted(latencies)[int(len(latencies)*0.95)]:.2f}ms")
            logger.info(f"Send latency (p99): {sorted(latencies)[int(len(latencies)*0.99)]:.2f}ms")
        
        # Queue depth
        if self.stats['queue_depths']:
            depths = [d['depth'] for d in self.stats['queue_depths']]
            max_depth = max(depths)
            avg_depth = sum(depths) / len(depths)
            logger.info(f"Max queue depth: {max_depth}")
            logger.info(f"Avg queue depth: {avg_depth:.1f}")
            
            if max_depth > 1000:
                logger.warning("⚠️  Queue depth exceeded 1000 - consider adding workers")
            else:
                logger.info("✅ Queue depth stayed within limits")
        
        # Final queue state
        try:
            final_depth = self.redis_client.llen(self.queue)
            logger.info(f"Final queue depth: {final_depth}")
        except:
            pass
        
        logger.info("="*60)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Load test for Intelligence Analyzer")
    parser.add_argument('--rate', type=int, default=100, help='Logs per second')
    parser.add_argument('--duration', type=int, default=60, help='Test duration in seconds')
    parser.add_argument('--queue', type=str, default='ingest_logs', help='Target queue')
    parser.add_argument('--tenants', type=int, default=5, help='Number of tenants')
    parser.add_argument('--attack-ratio', type=float, default=0.05, help='Ratio of attack logs')
    parser.add_argument('--redis-url', type=str, default='redis://localhost:6379/0', help='Redis URL')
    
    args = parser.parse_args()
    
    engine = LoadTestEngine(
        redis_url=args.redis_url,
        rate=args.rate,
        duration=args.duration,
        queue=args.queue,
        num_tenants=args.tenants,
        attack_ratio=args.attack_ratio
    )
    
    engine.run()


if __name__ == "__main__":
    main()
