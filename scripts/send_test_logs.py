#!/usr/bin/env python3
"""Sample script to send test logs to Redis."""

import redis
import json
from datetime import datetime
import random
import time

# Configuration
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_QUEUE = 'siem:logs'

# Sample IPs
SOURCE_IPS = [
    '192.168.1.100',
    '192.168.1.101',
    '10.0.0.50',
    '172.16.0.20',
    '203.0.113.10'  # Malicious IP (example)
]

DEST_IPS = [
    '10.0.0.5',
    '10.0.0.10',
    '172.16.1.1',
    '192.168.100.50'
]

# Log types
LOG_TYPES = ['auth', 'firewall', 'network', 'application']
PROTOCOLS = ['TCP', 'UDP', 'ICMP']
ACTIONS = ['allow', 'deny', 'failed', 'success']


def generate_auth_log(failed=False):
    """Generate an authentication log."""
    return {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source_ip': random.choice(SOURCE_IPS),
        'destination_ip': random.choice(DEST_IPS),
        'source_port': random.randint(40000, 65000),
        'destination_port': 22,
        'protocol': 'TCP',
        'action': 'failed' if failed else 'success',
        'log_type': 'auth',
        'message': f'SSH authentication {"failed" if failed else "succeeded"} for user admin'
    }


def generate_network_log():
    """Generate a network connection log."""
    return {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source_ip': random.choice(SOURCE_IPS),
        'destination_ip': random.choice(DEST_IPS),
        'source_port': random.randint(40000, 65000),
        'destination_port': random.choice([80, 443, 22, 23, 21, 3389, 8080]),
        'protocol': random.choice(PROTOCOLS),
        'action': random.choice(ACTIONS),
        'log_type': 'network',
        'message': 'Network connection attempt'
    }


def generate_firewall_log():
    """Generate a firewall log."""
    return {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source_ip': random.choice(SOURCE_IPS),
        'destination_ip': random.choice(DEST_IPS),
        'source_port': random.randint(40000, 65000),
        'destination_port': random.choice([80, 443, 22, 3389]),
        'protocol': random.choice(PROTOCOLS),
        'action': random.choice(['allow', 'deny', 'drop']),
        'log_type': 'firewall',
        'message': 'Firewall rule matched'
    }


def simulate_brute_force_attack(r, count=10):
    """Simulate a brute force attack."""
    print(f"\nSimulating brute force attack with {count} failed attempts...")
    source_ip = '192.168.1.100'
    
    for i in range(count):
        log = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source_ip': source_ip,
            'destination_ip': '10.0.0.5',
            'source_port': random.randint(40000, 65000),
            'destination_port': 22,
            'protocol': 'TCP',
            'action': 'failed',
            'log_type': 'auth',
            'message': f'SSH authentication failed for user admin (attempt {i+1})'
        }
        r.rpush(REDIS_QUEUE, json.dumps(log))
        print(f"  Sent failed auth attempt {i+1}/{count}")
        time.sleep(0.5)


def simulate_port_scan(r, ports=15):
    """Simulate a port scanning attack."""
    print(f"\nSimulating port scan with {ports} unique ports...")
    source_ip = '192.168.1.101'
    dest_ip = '10.0.0.10'
    
    for port in range(20, 20 + ports):
        log = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'source_port': random.randint(40000, 65000),
            'destination_port': port,
            'protocol': 'TCP',
            'action': 'deny',
            'log_type': 'network',
            'message': f'Connection attempt to port {port}'
        }
        r.rpush(REDIS_QUEUE, json.dumps(log))
        print(f"  Sent connection to port {port}")
        time.sleep(0.3)


def send_random_logs(r, count=20):
    """Send random normal logs."""
    print(f"\nSending {count} random logs...")
    
    for i in range(count):
        log_type = random.choice(['auth', 'network', 'firewall'])
        
        if log_type == 'auth':
            log = generate_auth_log(failed=random.random() < 0.2)
        elif log_type == 'network':
            log = generate_network_log()
        else:
            log = generate_firewall_log()
        
        r.rpush(REDIS_QUEUE, json.dumps(log))
        print(f"  Sent {log_type} log {i+1}/{count}")
        time.sleep(0.2)


def main():
    """Main function."""
    print("SIEM Analyzer - Test Log Generator")
    print("="*50)
    
    # Connect to Redis
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )
        r.ping()
        print(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        print(f"Queue: {REDIS_QUEUE}\n")
    except redis.ConnectionError as e:
        print(f"Error: Could not connect to Redis: {e}")
        return
    
    while True:
        print("\nSelect test scenario:")
        print("1. Send random logs")
        print("2. Simulate brute force attack")
        print("3. Simulate port scan")
        print("4. Run all scenarios")
        print("5. Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == '1':
            count = input("Number of logs (default 20): ").strip()
            count = int(count) if count else 20
            send_random_logs(r, count)
        
        elif choice == '2':
            count = input("Number of failed attempts (default 10): ").strip()
            count = int(count) if count else 10
            simulate_brute_force_attack(r, count)
        
        elif choice == '3':
            ports = input("Number of ports to scan (default 15): ").strip()
            ports = int(ports) if ports else 15
            simulate_port_scan(r, ports)
        
        elif choice == '4':
            print("\nRunning all test scenarios...")
            send_random_logs(r, 20)
            time.sleep(2)
            simulate_brute_force_attack(r, 10)
            time.sleep(2)
            simulate_port_scan(r, 15)
            print("\nAll scenarios completed!")
        
        elif choice == '5':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")
        
        # Show queue size
        queue_size = r.llen(REDIS_QUEUE)
        print(f"\nCurrent queue size: {queue_size}")


if __name__ == '__main__':
    main()
