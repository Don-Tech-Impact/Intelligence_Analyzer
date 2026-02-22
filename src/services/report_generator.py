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
        """Generate professional HTML report content with executive design."""
        
        # Color constants for the template
        PRIMARY = "#0B1120"
        ACCENT = "#3B82F6"
        SUCCESS = "#22C55E"
        DANGER = "#EF4444"
        TEXT_DIM = "#64748B"
        
        # Calculate percentages/trends for the visual feel
        total_logs = data.get('total_logs', 0)
        total_alerts = data.get('total_alerts', 0)
        critical_alerts = data.get('alerts_by_severity', {}).get('critical', 0)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive Security Report | Intelligence Analyzer</title>
    <style>
        :root {{
            --primary: {PRIMARY};
            --accent: {ACCENT};
            --success: {SUCCESS};
            --danger: {DANGER};
            --text-dim: {TEXT_DIM};
        }}
        body {{ 
            font-family: 'Inter', system-ui, -apple-system, sans-serif; 
            margin: 0; padding: 0; background: #F8FAFC; color: #1E293B; line-height: 1.6;
        }}
        .sidebar-stripe {{ position: fixed; left: 0; top: 0; bottom: 0; width: 6px; background: var(--primary); }}
        .container {{ max-width: 900px; margin: 40px auto; background: white; padding: 50px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border-radius: 8px; }}
        
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; border-bottom: 1px solid #E2E8F0; padding-bottom: 30px; }}
        .logo-area {{ display: flex; align-items: center; gap: 15px; }}
        .logo-icon {{ background: var(--primary); color: white; width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 20px; }}
        .report-title {{ letter-spacing: -0.02em; font-weight: 800; font-size: 24px; color: var(--primary); }}
        
        .confidential-notice {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--danger); font-weight: 700; margin-bottom: 20px; }}
        
        .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; font-size: 13px; color: var(--text-dim); margin-bottom: 30px; }}
        .meta-item b {{ color: #1E293B; margin-right: 5px; }}
        
        .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }}
        .stat-card {{ background: #F1F5F9; padding: 20px; border-radius: 12px; border: 1px solid #E2E8F0; }}
        .stat-label {{ font-size: 12px; font-weight: 600; color: var(--text-dim); text-transform: uppercase; margin-bottom: 5px; }}
        .stat-value {{ font-size: 28px; font-weight: 800; color: var(--primary); }}
        .stat-card.alert {{ border-left: 4px solid var(--danger); }}
        
        h2 {{ font-size: 18px; font-weight: 700; margin-top: 40px; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }}
        h2::after {{ content: ''; flex: 1; height: 1px; background: #E2E8F0; }}
        
        table {{ border-collapse: collapse; width: 100%; font-size: 14px; margin-top: 10px; }}
        th {{ text-align: left; padding: 12px 15px; background: #F8FAFC; border-bottom: 2px solid #E2E8F0; color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #F1F5F9; }}
        
        .severity-pill {{ display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
        .sev-critical {{ background: rgba(239, 68, 68, 0.1); color: var(--danger); }}
        .sev-high {{ background: rgba(245, 158, 11, 0.1); color: #D97706; }}
        .sev-medium {{ background: rgba(59, 130, 246, 0.1); color: var(--accent); }}
        .sev-low {{ background: rgba(34, 197, 94, 0.1); color: var(--success); }}
        
        .footer {{ margin-top: 60px; padding-top: 20px; border-top: 1px solid #E2E8F0; font-size: 12px; color: var(--text-dim); text-align: center; }}
        
        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; margin: 0; width: 100%; max-width: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="sidebar-stripe"></div>
    <div class="container">
        <div class="confidential-notice">Security Classification: Internal Use Only</div>
        
        <div class="header">
            <div class="logo-area">
                <div class="logo-icon">A</div>
                <div>
                    <div class="report-title">Security Intelligence Executive Summary</div>
                    <div style="color: var(--text-dim); font-size: 14px;">Intelligence Analyzer Platform</div>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-weight: 700; font-size: 12px;">VERSION 1.0</div>
                <div style="font-size: 12px; color: var(--text-dim);">ID: {datetime.utcnow().strftime('%Y-%j')}</div>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-item"><b>REPORT PERIOD:</b> {start_date.strftime('%b %d, %Y')} &mdash; {end_date.strftime('%b %d, %Y')}</div>
            <div class="meta-item"><b>GENERATED ON:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
            <div class="meta-item"><b>TENANT SCOPE:</b> {data.get('tenant_id', 'Enterprise Default')}</div>
            <div class="meta-item"><b>COMPLIANCE SCOPE:</b> SOC2 / ISO 27001 Baseline</div>
        </div>

        <div class="summary-grid">
            <div class="stat-card">
                <div class="stat-label">Ingested Logs</div>
                <div class="stat-value">{total_logs:,}</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-label">Security Alerts</div>
                <div class="stat-value">{total_alerts:,}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical Risks</div>
                <div class="stat-value" style="color: var(--danger);">{critical_alerts}</div>
            </div>
        </div>

        <h2>Risk Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Risk Severity</th>
                    <th>Incident Count</th>
                    <th>Proportional Volume</th>
                </tr>
            </thead>
            <tbody>
"""
        
        severities = ['critical', 'high', 'medium', 'low']
        for sev in severities:
            count = data.get('alerts_by_severity', {}).get(sev, 0)
            percent = (count / total_alerts * 100) if total_alerts > 0 else 0
            html += f"""
                <tr>
                    <td><span class="severity-pill sev-{sev}">{sev}</span></td>
                    <td><b>{count}</b></td>
                    <td>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <div style="flex:1; height:6px; background:#F1F5F9; border-radius:3px; overflow:hidden;">
                                <div style="width:{percent}%; height:100%; background:var(--primary);"></div>
                            </div>
                            <span style="font-size:11px; width:35px;">{percent:.1f}%</span>
                        </div>
                    </td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>

        <h2>Top Threat Vectors</h2>
        <table>
            <thead>
                <tr>
                    <th>Threat Indicator</th>
                    <th>Detection Count</th>
                </tr>
            </thead>
            <tbody>
"""
        
        alert_types = sorted(data.get('alerts_by_type', {}).items(), key=lambda x: x[1], reverse=True)[:5]
        if not alert_types:
            html += "<tr><td colspan='2' style='text-align:center;'>No significant threat vectors detected during this period.</td></tr>"
        else:
            for alert_type, count in alert_types:
                html += f"<tr><td>{alert_type.replace('_', ' ').title()}</td><td><b>{count}</b></td></tr>"
        
        html += """
            </tbody>
        </table>

        <h2>High-Risk Source Activity</h2>
        <table>
            <thead>
                <tr>
                    <th>Source IP Address</th>
                    <th>Infrastructure Impact</th>
                </tr>
            </thead>
            <tbody>
"""
        
        top_ips = data.get('top_source_ips', {})
        if not top_ips:
             html += "<tr><td colspan='2' style='text-align:center;'>Minimal anomalous source activity detected.</td></tr>"
        else:
            for ip, count in top_ips.items():
                html += f"<tr><td style='font-family: monospace;'>{ip}</td><td><b>{count}</b> events recorded</td></tr>"

        html += f"""
            </tbody>
        </table>

        <div class="footer">
            &copy; {datetime.utcnow().year} Intelligence Analyzer SIEM Platform. All rights reserved.<br>
            This document contains proprietary information and is intended for use by authorized personnel only.
        </div>
    </div>
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
