#!/usr/bin/env python3
"""Setup script to initialize SIEM Analyzer."""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.config import config
from src.core.database import db_manager
from src.core.logging_config import setup_logging


def main():
    """Initialize the SIEM Analyzer."""
    print("="*60)
    print("SIEM Analyzer - Initialization")
    print("="*60)
    
    # Setup logging
    print("\n1. Setting up logging...")
    setup_logging()
    print("   ✓ Logging configured")
    
    # Create necessary directories
    print("\n2. Creating directories...")
    directories = ['logs', 'reports', 'config']
    for directory in directories:
        dir_path = project_root / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"   ✓ {directory}/")
    
    # Initialize database
    print("\n3. Initializing database...")
    try:
        db_manager.initialize()
        print(f"   ✓ Database initialized: {config.database_type}")
        print(f"   ✓ Database URL: {config.database_url.split('@')[-1] if '@' in config.database_url else config.database_url}")
    except Exception as e:
        print(f"   ✗ Database initialization failed: {e}")
        return 1
    
    # Display configuration
    print("\n4. Configuration Summary:")
    print(f"   Redis Host: {config.redis_host}:{config.redis_port}")
    print(f"   Redis Queue: {config.redis_log_queue}")
    print(f"   Email Alerts: {'Enabled' if config.email_enabled else 'Disabled'}")
    print(f"   Reports: {'Enabled' if config.report_enabled else 'Disabled'}")
    print(f"   Threat Intel: {'Enabled' if config.threat_intel_enabled else 'Disabled'}")
    print(f"   Multi-tenant: {'Enabled' if config.multi_tenant_enabled else 'Disabled'}")
    
    print("\n" + "="*60)
    print("SIEM Analyzer initialized successfully!")
    print("="*60)
    print("\nNext steps:")
    print("1. Review configuration in config/config.yaml")
    print("2. Start the analyzer: python -m src.main")
    print("3. Send test logs: python scripts/send_test_logs.py")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
