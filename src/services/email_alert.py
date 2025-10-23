"""Email alerting service."""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from datetime import datetime

from src.models.database import Alert
from src.core.config import config

logger = logging.getLogger(__name__)


class EmailAlertService:
    """Sends email notifications for security alerts."""
    
    def __init__(self):
        """Initialize email alert service."""
        self.enabled = config.email_enabled
        self.smtp_host = config.smtp_host
        self.smtp_port = config.smtp_port
        self.smtp_user = config.smtp_user
        self.smtp_password = config.smtp_password
        self.use_tls = config.smtp_use_tls
        self.from_address = config.email_from
        self.to_addresses = config.email_to
    
    def send_alert(self, alert: Alert) -> bool:
        """Send email notification for an alert.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            logger.debug("Email alerts are disabled")
            return False
        
        try:
            subject = self._create_subject(alert)
            body = self._create_body(alert)
            
            return self._send_email(subject, body, self.to_addresses)
        
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
            return False
    
    def send_batch_alerts(self, alerts: List[Alert]) -> bool:
        """Send batch email for multiple alerts.
        
        Args:
            alerts: List of alerts to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled or not alerts:
            return False
        
        try:
            subject = f"SIEM Alert Batch - {len(alerts)} Alerts"
            body = self._create_batch_body(alerts)
            
            return self._send_email(subject, body, self.to_addresses)
        
        except Exception as e:
            logger.error(f"Failed to send batch alert email: {e}")
            return False
    
    def _create_subject(self, alert: Alert) -> str:
        """Create email subject line.
        
        Args:
            alert: Alert object
            
        Returns:
            Email subject string
        """
        return f"[{alert.severity.upper()}] SIEM Alert - {alert.alert_type}"
    
    def _create_body(self, alert: Alert) -> str:
        """Create email body content.
        
        Args:
            alert: Alert object
            
        Returns:
            Email body string
        """
        body = f"""
SIEM Security Alert

Alert ID: {alert.id}
Severity: {alert.severity.upper()}
Type: {alert.alert_type}
Status: {alert.status}

Description:
{alert.description}

Details:
Source IP: {alert.source_ip or 'N/A'}
Destination IP: {alert.destination_ip or 'N/A'}
Tenant: {alert.tenant_id}

Created At: {alert.created_at}

Additional Details:
{self._format_details(alert.details)}

---
This is an automated alert from the SIEM Analyzer system.
"""
        return body
    
    def _create_batch_body(self, alerts: List[Alert]) -> str:
        """Create email body for batch alerts.
        
        Args:
            alerts: List of alerts
            
        Returns:
            Email body string
        """
        # Count by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        body = f"""
SIEM Security Alert Batch

Total Alerts: {len(alerts)}
"""
        
        # Add severity breakdown
        body += "\nAlerts by Severity:\n"
        for severity, count in sorted(severity_counts.items()):
            body += f"  {severity.upper()}: {count}\n"
        
        body += "\n" + "="*60 + "\n\n"
        
        # Add individual alerts
        for i, alert in enumerate(alerts, 1):
            body += f"Alert {i}:\n"
            body += f"  ID: {alert.id}\n"
            body += f"  Severity: {alert.severity.upper()}\n"
            body += f"  Type: {alert.alert_type}\n"
            body += f"  Source IP: {alert.source_ip or 'N/A'}\n"
            body += f"  Description: {alert.description[:100]}...\n"
            body += f"  Created: {alert.created_at}\n"
            body += "\n" + "-"*60 + "\n\n"
        
        body += """
---
This is an automated alert from the SIEM Analyzer system.
"""
        return body
    
    def _format_details(self, details: dict) -> str:
        """Format alert details dictionary.
        
        Args:
            details: Alert details dictionary
            
        Returns:
            Formatted string
        """
        if not details:
            return "No additional details"
        
        lines = []
        for key, value in details.items():
            lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
    
    def _send_email(
        self, 
        subject: str, 
        body: str, 
        to_addresses: List[str]
    ) -> bool:
        """Send email via SMTP.
        
        Args:
            subject: Email subject
            body: Email body
            to_addresses: List of recipient addresses
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_address
            msg['To'] = ', '.join(to_addresses)
            msg['Subject'] = subject
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            # Attach body
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            
            # Login if credentials provided
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent successfully to {', '.join(to_addresses)}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test SMTP connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
            
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            
            server.quit()
            logger.info("SMTP connection test successful")
            return True
        
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False
