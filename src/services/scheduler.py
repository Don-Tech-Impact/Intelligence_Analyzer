"""Scheduler for automated tasks."""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime

from src.services.threat_intel_updater import ThreatIntelUpdater
from src.services.report_generator import ReportGenerator
from src.services.email_alert import EmailAlertService
from src.core.config import config
from src.core.database import db_manager
from src.models.database import Alert

logger = logging.getLogger(__name__)


class TaskScheduler:
    """Manages scheduled tasks for the SIEM analyzer."""
    
    def __init__(self):
        """Initialize task scheduler."""
        self.scheduler = BackgroundScheduler()
        self.threat_intel_updater = ThreatIntelUpdater()
        self.report_generator = ReportGenerator()
        self.email_service = EmailAlertService()
    
    def start(self):
        """Start the scheduler and all scheduled tasks."""
        logger.info("Starting task scheduler")
        
        # Schedule threat intelligence updates
        if config.threat_intel_enabled:
            interval_seconds = config.threat_intel_update_interval
            self.scheduler.add_job(
                func=self._update_threat_intelligence,
                trigger='interval',
                seconds=interval_seconds,
                id='threat_intel_update',
                name='Update Threat Intelligence Feeds',
                replace_existing=True
            )
            logger.info(f"Scheduled threat intelligence updates every {interval_seconds} seconds")
        
        # Schedule daily reports
        if config.report_enabled:
            cron_schedule = config.report_schedule
            trigger = CronTrigger.from_crontab(cron_schedule)
            self.scheduler.add_job(
                func=self._generate_daily_report,
                trigger=trigger,
                id='daily_report',
                name='Generate Daily Report',
                replace_existing=True
            )
            logger.info(f"Scheduled daily reports with cron: {cron_schedule}")
        
        # Schedule alert notifications (check every 5 minutes)
        if config.email_enabled:
            self.scheduler.add_job(
                func=self._send_pending_alerts,
                trigger='interval',
                minutes=5,
                id='alert_notifications',
                name='Send Pending Alert Notifications',
                replace_existing=True
            )
            logger.info("Scheduled alert notifications every 5 minutes")
        
        # Start the scheduler
        self.scheduler.start()
        logger.info("Task scheduler started")
    
    def stop(self):
        """Stop the scheduler."""
        logger.info("Stopping task scheduler")
        self.scheduler.shutdown()
        logger.info("Task scheduler stopped")
    
    def _update_threat_intelligence(self):
        """Task: Update threat intelligence feeds."""
        try:
            logger.info("Running scheduled threat intelligence update")
            self.threat_intel_updater.update_all_feeds()
        except Exception as e:
            logger.error(f"Error in scheduled threat intelligence update: {e}", exc_info=True)
    
    def _generate_daily_report(self):
        """Task: Generate daily security report."""
        try:
            logger.info("Running scheduled daily report generation")
            report = self.report_generator.generate_daily_report()
            
            if report and config.email_enabled:
                # Send report via email
                self._send_report_email(report)
        except Exception as e:
            logger.error(f"Error in scheduled report generation: {e}", exc_info=True)
    
    def _send_pending_alerts(self):
        """Task: Send pending alert notifications."""
        try:
            logger.info("Checking for pending alert notifications")
            
            # Get unnotified alerts
            with db_manager.session_scope() as session:
                alerts = session.query(Alert).filter(
                    Alert.notified == False,
                    Alert.status == 'open'
                ).limit(50).all()
                
                if not alerts:
                    logger.debug("No pending alerts to notify")
                    return
                
                logger.info(f"Sending notifications for {len(alerts)} alerts")
                
                # Send alerts in batch
                if self.email_service.send_batch_alerts(alerts):
                    # Mark alerts as notified
                    for alert in alerts:
                        alert.notified = True
                    session.commit()
                    logger.info(f"Successfully notified {len(alerts)} alerts")
                else:
                    logger.warning("Failed to send alert notifications")
        
        except Exception as e:
            logger.error(f"Error in alert notification task: {e}", exc_info=True)
    
    def _send_report_email(self, report):
        """Send report via email.
        
        Args:
            report: Report object
        """
        try:
            # Read report file
            with open(report.file_path, 'r') as f:
                report_content = f.read()
            
            # Send email to report recipients
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import smtplib
            
            msg = MIMEMultipart()
            msg['From'] = config.email_from
            msg['To'] = ', '.join(config.report_email_to)
            msg['Subject'] = f"SIEM {report.report_type.title()} Report - {report.start_date.strftime('%Y-%m-%d')}"
            
            # Attach HTML report
            msg.attach(MIMEText(report_content, 'html'))
            
            # Send email
            if config.smtp_use_tls:
                server = smtplib.SMTP(config.smtp_host, config.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(config.smtp_host, config.smtp_port)
            
            if config.smtp_user and config.smtp_password:
                server.login(config.smtp_user, config.smtp_password)
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Report email sent successfully")
        
        except Exception as e:
            logger.error(f"Failed to send report email: {e}")
    
    def run_task_now(self, task_id: str):
        """Manually trigger a scheduled task.
        
        Args:
            task_id: Task identifier
        """
        job = self.scheduler.get_job(task_id)
        if job:
            logger.info(f"Manually triggering task: {task_id}")
            job.modify(next_run_time=datetime.now())
        else:
            logger.warning(f"Task not found: {task_id}")
