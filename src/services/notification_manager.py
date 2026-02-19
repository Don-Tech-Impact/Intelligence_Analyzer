from typing import List
from src.models.database import Alert
from src.services.email_alert import EmailAlertService
from src.services.webhook_alert import WebhookAlertService

class NotificationManager:
    """Manager to handle all types of alert notifications."""
    
    def __init__(self):
        self.email_service = EmailAlertService()
        self.webhook_service = WebhookAlertService()

    def notify(self, alert: Alert):
        """Notify via all enabled channels."""
        # Only notify for important severities by default
        if alert.severity in ['high', 'critical']:
            self.email_service.send_alert(alert)
            self.webhook_service.send_alert(alert)

# Global instance
notification_manager = NotificationManager()
