"""Reporting service for generating security reports."""

import logging
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path

from src.models.database import NormalizedLog, Alert, Report
from src.core.database import db_manager
from src.core.config import config

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security reports from log and alert data."""
    
    def __init__(self, output_dir: str = 'reports'):
        """Initialize report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_daily_report(
        self, 
        date: Optional[datetime] = None,
        tenant_id: str = 'default'
    ) -> Optional[Report]:
        """Generate daily security report.
        
        Args:
            date: Date for report (defaults to yesterday)
            tenant_id: Tenant identifier
            
        Returns:
            Report object if generated successfully
        """
        if date is None:
            date = datetime.utcnow().date() - timedelta(days=1)
        
        start_date = datetime.combine(date, datetime.min.time())
        end_date = datetime.combine(date, datetime.max.time())
        
        return self.generate_report(
            start_date=start_date,
            end_date=end_date,
            report_type='daily',
            tenant_id=tenant_id
        )
    
    def generate_report(
        self,
        start_date: datetime,
        end_date: datetime,
        report_type: str = 'custom',
        tenant_id: str = 'default'
    ) -> Optional[Report]:
        """Generate a security report for the specified time period.
        
        Args:
            start_date: Report start date
            end_date: Report end date
            report_type: Type of report (daily, weekly, monthly, custom)
            tenant_id: Tenant identifier
            
        Returns:
            Report object if generated successfully
        """
        try:
            logger.info(f"Generating {report_type} report from {start_date} to {end_date}")
            
            # Collect report data
            report_data = self._collect_report_data(
                start_date, 
                end_date, 
                tenant_id
            )
            
            # Generate report files
            report_files = self._generate_report_files(
                report_data,
                start_date,
                end_date,
                report_type
            )
            
            # Save report metadata to database
            report = self._save_report_metadata(
                start_date=start_date,
                end_date=end_date,
                report_type=report_type,
                tenant_id=tenant_id,
                report_data=report_data,
                file_path=report_files.get('html', '')
            )
            
            logger.info(f"Report generated successfully: {report.id}")
            return report
        
        except Exception as e:
            logger.error(f"Failed to generate report: {e}", exc_info=True)
            return None
    
    def _collect_report_data(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Collect data for report.
        
        Args:
            start_date: Start date
            end_date: End date
            tenant_id: Tenant identifier
            
        Returns:
            Dictionary containing report data
        """
        data = {}
        
        with db_manager.session_scope() as session:
            # Total logs
            data['total_logs'] = session.query(NormalizedLog).filter(
                NormalizedLog.tenant_id == tenant_id,
                NormalizedLog.timestamp >= start_date,
                NormalizedLog.timestamp <= end_date
            ).count()
            
            # Total alerts
            data['total_alerts'] = session.query(Alert).filter(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= start_date,
                Alert.created_at <= end_date
            ).count()
            
            # Alerts by severity
            alerts = session.query(Alert).filter(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= start_date,
                Alert.created_at <= end_date
            ).all()
            
            severity_counts = {}
            alert_type_counts = {}
            source_ip_counts = {}
            
            for alert in alerts:
                # Count by severity
                severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
                
                # Count by type
                alert_type_counts[alert.alert_type] = alert_type_counts.get(alert.alert_type, 0) + 1
                
                # Count by source IP
                if alert.source_ip:
                    source_ip_counts[alert.source_ip] = source_ip_counts.get(alert.source_ip, 0) + 1
            
            data['alerts_by_severity'] = severity_counts
            data['alerts_by_type'] = alert_type_counts
            
            # Top 10 source IPs
            top_sources = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            data['top_source_ips'] = dict(top_sources)
            
            # Logs by type
            logs = session.query(NormalizedLog).filter(
                NormalizedLog.tenant_id == tenant_id,
                NormalizedLog.timestamp >= start_date,
                NormalizedLog.timestamp <= end_date
            ).all()
            
            log_type_counts = {}
            for log in logs:
                log_type = log.log_type or 'unknown'
                log_type_counts[log_type] = log_type_counts.get(log_type, 0) + 1
            
            data['logs_by_type'] = log_type_counts
        
        return data
    
    def _generate_report_files(
        self,
        report_data: Dict[str, Any],
        start_date: datetime,
        end_date: datetime,
        report_type: str
    ) -> Dict[str, str]:
        """Generate report files in various formats.
        
        Args:
            report_data: Report data dictionary
            start_date: Start date
            end_date: End date
            report_type: Report type
            
        Returns:
            Dictionary of format -> file path
        """
        files = {}
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{report_type}_report_{timestamp}"
        
        # Generate HTML report
        html_file = self.output_dir / f"{base_filename}.html"
        html_content = self._generate_html_report(report_data, start_date, end_date)
        html_file.write_text(html_content)
        files['html'] = str(html_file)
        logger.info(f"HTML report saved to: {html_file}")
        
        # Generate CSV report
        csv_file = self.output_dir / f"{base_filename}.csv"
        self._generate_csv_report(report_data, csv_file)
        files['csv'] = str(csv_file)
        logger.info(f"CSV report saved to: {csv_file}")
        
        return files
    
    def _generate_html_report(
        self,
        data: Dict[str, Any],
        start_date: datetime,
        end_date: datetime
    ) -> str:
        """Generate HTML report content.
        
        Args:
            data: Report data
            start_date: Start date
            end_date: End date
            
        Returns:
            HTML string
        """
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .summary {{ background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; }}
    </style>
</head>
<body>
    <h1>SIEM Security Report</h1>
    <div class="summary">
        <p><strong>Report Period:</strong> {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}</p>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    </div>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Total Logs</td><td>{data.get('total_logs', 0):,}</td></tr>
        <tr><td>Total Alerts</td><td>{data.get('total_alerts', 0):,}</td></tr>
    </table>
    
    <h2>Alerts by Severity</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
"""
        
        for severity, count in sorted(data.get('alerts_by_severity', {}).items()):
            severity_class = severity.lower()
            html += f"        <tr><td class='{severity_class}'>{severity.upper()}</td><td>{count}</td></tr>\n"
        
        html += """
    </table>
    
    <h2>Alerts by Type</h2>
    <table>
        <tr><th>Alert Type</th><th>Count</th></tr>
"""
        
        for alert_type, count in sorted(data.get('alerts_by_type', {}).items(), key=lambda x: x[1], reverse=True):
            html += f"        <tr><td>{alert_type}</td><td>{count}</td></tr>\n"
        
        html += """
    </table>
    
    <h2>Top Source IPs</h2>
    <table>
        <tr><th>IP Address</th><th>Alert Count</th></tr>
"""
        
        for ip, count in data.get('top_source_ips', {}).items():
            html += f"        <tr><td>{ip}</td><td>{count}</td></tr>\n"
        
        html += """
    </table>
</body>
</html>
"""
        return html
    
    def _generate_csv_report(
        self,
        data: Dict[str, Any],
        output_file: Path
    ):
        """Generate CSV report.
        
        Args:
            data: Report data
            output_file: Output file path
        """
        # Create summary DataFrame
        summary_data = {
            'Metric': ['Total Logs', 'Total Alerts'],
            'Count': [data.get('total_logs', 0), data.get('total_alerts', 0)]
        }
        df_summary = pd.DataFrame(summary_data)
        
        # Write to CSV with multiple sections
        with open(output_file, 'w') as f:
            f.write("SIEM Security Report\n\n")
            f.write("Summary\n")
            df_summary.to_csv(f, index=False)
            
            f.write("\n\nAlerts by Severity\n")
            df_severity = pd.DataFrame(
                list(data.get('alerts_by_severity', {}).items()),
                columns=['Severity', 'Count']
            )
            df_severity.to_csv(f, index=False)
            
            f.write("\n\nAlerts by Type\n")
            df_types = pd.DataFrame(
                list(data.get('alerts_by_type', {}).items()),
                columns=['Alert Type', 'Count']
            )
            df_types.to_csv(f, index=False)
            
            f.write("\n\nTop Source IPs\n")
            df_ips = pd.DataFrame(
                list(data.get('top_source_ips', {}).items()),
                columns=['IP Address', 'Alert Count']
            )
            df_ips.to_csv(f, index=False)
    
    def _save_report_metadata(
        self,
        start_date: datetime,
        end_date: datetime,
        report_type: str,
        tenant_id: str,
        report_data: Dict[str, Any],
        file_path: str
    ) -> Report:
        """Save report metadata to database.
        
        Args:
            start_date: Start date
            end_date: End date
            report_type: Report type
            tenant_id: Tenant identifier
            report_data: Report data
            file_path: Path to report file
            
        Returns:
            Report object
        """
        with db_manager.session_scope() as session:
            session.expire_on_commit = False
            report = Report(
                tenant_id=tenant_id,
                report_type=report_type,
                start_date=start_date,
                end_date=end_date,
                total_logs=report_data.get('total_logs', 0),
                total_alerts=report_data.get('total_alerts', 0),
                alerts_by_severity=report_data.get('alerts_by_severity', {}),
                top_source_ips=report_data.get('top_source_ips', {}),
                top_alert_types=report_data.get('alerts_by_type', {}),
                file_path=file_path,
                format='html'
            )
            session.add(report)
            return report
