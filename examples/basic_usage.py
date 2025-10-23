"""Example: Basic usage of the SIEM Analyzer."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.logging_config import setup_logging
from src.core.database import db_manager
from src.models.database import Log, Alert
from datetime import datetime


def main():
    """Example of basic SIEM Analyzer usage."""
    
    # Setup logging
    setup_logging()
    
    # Initialize database
    db_manager.initialize()
    
    # Example 1: Create a log entry
    print("Example 1: Creating a log entry")
    with db_manager.session_scope() as session:
        log = Log(
            source_ip='192.168.1.100',
            destination_ip='10.0.0.5',
            source_port=54321,
            destination_port=22,
            protocol='TCP',
            action='failed',
            log_type='auth',
            message='SSH authentication failed'
        )
        session.add(log)
        session.commit()
        print(f"Created log entry: {log.id}")
    
    # Example 2: Query logs
    print("\nExample 2: Querying logs")
    with db_manager.session_scope() as session:
        logs = session.query(Log).limit(10).all()
        print(f"Found {len(logs)} logs")
        for log in logs:
            print(f"  - {log.source_ip} -> {log.destination_ip} ({log.log_type})")
    
    # Example 3: Create an alert
    print("\nExample 3: Creating an alert")
    with db_manager.session_scope() as session:
        alert = Alert(
            alert_type='brute_force',
            severity='high',
            source_ip='192.168.1.100',
            description='Brute force attack detected',
            details={'attempts': 10, 'time_window': 300},
            status='open'
        )
        session.add(alert)
        session.commit()
        print(f"Created alert: {alert.id}")
    
    # Example 4: Query alerts
    print("\nExample 4: Querying alerts")
    with db_manager.session_scope() as session:
        alerts = session.query(Alert).filter(
            Alert.status == 'open'
        ).all()
        print(f"Found {len(alerts)} open alerts")
        for alert in alerts:
            print(f"  - [{alert.severity}] {alert.alert_type}: {alert.description}")
    
    print("\nExample completed!")


if __name__ == '__main__':
    main()
