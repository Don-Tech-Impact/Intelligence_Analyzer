import logging
import requests
from typing import Optional
from src.models.database import Alert
from src.core.config import config

logger = logging.getLogger(__name__)

class WebhookAlertService:
    """Sends notifications to Discord or Slack."""
    
    def __init__(self):
        self.enabled = config.webhooks_enabled
        self.discord_url = config.discord_webhook_url
        self.slack_url = config.slack_webhook_url

    def send_alert(self, alert: Alert):
        if not self.enabled:
            return

        message = (
            f"🚨 **SIEM ALERT: {alert.alert_type}**\n"
            f"**Severity**: {alert.severity.upper()}\n"
            f"**Source IP**: {alert.source_ip}\n"
            f"**Description**: {alert.description}\n"
            f"**Tenant**: {alert.tenant_id}"
        )

        if self.discord_url:
            self._send_to_discord(message)
        
        if self.slack_url:
            self._send_to_slack(message)

    def _send_to_discord(self, message: str):
        try:
            requests.post(self.discord_url, json={"content": message}, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")

    def _send_to_slack(self, message: str):
        try:
            requests.post(self.slack_url, json={"text": message}, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
