#!/usr/bin/env python3
"""Query tool for SIEM Analyzer database."""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.config import config
from src.core.database import db_manager
from src.models.database import Log, Alert, ThreatIntelligence, Report


def show_statistics():
    """Display database statistics."""
    print("\n" + "="*60)
    print("SIEM Analyzer - Database Statistics")
    print("="*60)
    
    db_manager.initialize()
    
    with db_manager.session_scope() as session:
        # Logs
        total_logs = session.query(Log).count()
        logs_today = session.query(Log).filter(
            Log.timestamp >= datetime.utcnow().date()
        ).count()
        
        # Alerts
        total_alerts = session.query(Alert).count()
        open_alerts = session.query(Alert).filter(
            Alert.status == 'open'
        ).count()
        
        alerts_by_severity = {}
        for severity in ['low', 'medium', 'high', 'critical']:
            count = session.query(Alert).filter(
                Alert.severity == severity,
                Alert.status == 'open'
            ).count()
            alerts_by_severity[severity] = count
        
        # Threat Intelligence
        total_indicators = session.query(ThreatIntelligence).count()
        active_indicators = session.query(ThreatIntelligence).filter(
            ThreatIntelligence.is_active == True
        ).count()
        
        # Reports
        total_reports = session.query(Report).count()
        
        print(f"\n📊 Logs:")
        print(f"   Total logs: {total_logs:,}")
        print(f"   Logs today: {logs_today:,}")
        
        print(f"\n🚨 Alerts:")
        print(f"   Total alerts: {total_alerts:,}")
        print(f"   Open alerts: {open_alerts:,}")
        print(f"   By severity:")
        for severity, count in alerts_by_severity.items():
            print(f"     - {severity.capitalize()}: {count}")
        
        print(f"\n🔍 Threat Intelligence:")
        print(f"   Total indicators: {total_indicators:,}")
        print(f"   Active indicators: {active_indicators:,}")
        
        print(f"\n📈 Reports:")
        print(f"   Total reports: {total_reports:,}")
        
        print("\n" + "="*60)


def list_recent_alerts(limit=10):
    """List recent alerts."""
    print(f"\n🚨 Recent Alerts (last {limit}):")
    print("-"*60)
    
    db_manager.initialize()
    
    with db_manager.session_scope() as session:
        alerts = session.query(Alert).order_by(
            Alert.created_at.desc()
        ).limit(limit).all()
        
        if not alerts:
            print("No alerts found.")
            return
        
        for alert in alerts:
            print(f"\n[{alert.severity.upper()}] {alert.alert_type}")
            print(f"  ID: {alert.id}")
            print(f"  Source IP: {alert.source_ip}")
            print(f"  Status: {alert.status}")
            print(f"  Created: {alert.created_at}")
            print(f"  Description: {alert.description[:100]}...")


def list_top_source_ips(limit=10):
    """List top source IPs by alert count."""
    print(f"\n🌐 Top {limit} Source IPs by Alerts:")
    print("-"*60)
    
    db_manager.initialize()
    
    with db_manager.session_scope() as session:
        from sqlalchemy import func
        
        results = session.query(
            Alert.source_ip,
            func.count(Alert.id).label('alert_count')
        ).filter(
            Alert.source_ip.isnot(None)
        ).group_by(
            Alert.source_ip
        ).order_by(
            func.count(Alert.id).desc()
        ).limit(limit).all()
        
        if not results:
            print("No data available.")
            return
        
        for i, (ip, count) in enumerate(results, 1):
            print(f"{i:2d}. {ip:15s} - {count:3d} alerts")


def search_logs(source_ip=None, dest_ip=None, log_type=None, limit=10):
    """Search logs with filters."""
    print(f"\n🔎 Searching Logs:")
    print("-"*60)
    
    db_manager.initialize()
    
    with db_manager.session_scope() as session:
        query = session.query(Log)
        
        if source_ip:
            query = query.filter(Log.source_ip == source_ip)
        if dest_ip:
            query = query.filter(Log.destination_ip == dest_ip)
        if log_type:
            query = query.filter(Log.log_type == log_type)
        
        logs = query.order_by(Log.timestamp.desc()).limit(limit).all()
        
        if not logs:
            print("No logs found matching criteria.")
            return
        
        print(f"Found {len(logs)} logs:\n")
        for log in logs:
            print(f"[{log.timestamp}] {log.source_ip} -> {log.destination_ip}")
            print(f"  Type: {log.log_type}, Action: {log.action}")
            print(f"  Message: {log.message}")
            print()


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM Analyzer Query Tool')
    parser.add_argument('command', choices=['stats', 'alerts', 'top-ips', 'search'],
                        help='Command to execute')
    parser.add_argument('--limit', type=int, default=10,
                        help='Limit number of results')
    parser.add_argument('--source-ip', help='Filter by source IP')
    parser.add_argument('--dest-ip', help='Filter by destination IP')
    parser.add_argument('--log-type', help='Filter by log type')
    
    args = parser.parse_args()
    
    try:
        if args.command == 'stats':
            show_statistics()
        elif args.command == 'alerts':
            list_recent_alerts(args.limit)
        elif args.command == 'top-ips':
            list_top_source_ips(args.limit)
        elif args.command == 'search':
            search_logs(args.source_ip, args.dest_ip, args.log_type, args.limit)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
