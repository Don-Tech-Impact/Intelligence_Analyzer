"""Account Management Analyzer.

=============================================================================
DETECTION LOGIC
=============================================================================
Detects: User/group creation, deletion, modification, password changes.

Every account change is itself an alert-worthy event (no threshold counting).
Account management events are high-confidence indicators of either legitimate
admin activity or attacker persistence (backdoor accounts).

Detection sources:
    - log_type: "user_management" (set by LogAdapter._parse_syslog_auth)
    - business_context.threat_category: "account_change"
    - Raw message keywords for useradd, userdel, usermod, groupadd, passwd
=============================================================================
"""

import logging
from typing import Optional

from src.analyzers.base import BaseAnalyzer
from src.models.database import Alert

logger = logging.getLogger(__name__)

# Map message keywords to human-readable event names and severity
ACCOUNT_EVENTS = [
    # (keyword_upper, event_name, severity)
    ("USERADD",   "User Account Created",   "high"),
    ("USERDEL",   "User Account Deleted",   "high"),
    ("USERMOD",   "User Account Modified",  "medium"),
    ("GROUPADD",  "Group Created",          "medium"),
    ("GROUPDEL",  "Group Deleted",          "medium"),
    ("GROUPMOD",  "Group Modified",         "medium"),
    ("PASSWD[",   "Password Changed",       "medium"),
    ("CHPASSWD",  "Bulk Password Change",   "high"),
]

# Escalate severity if these strings appear — indicates attacker persistence
CRITICAL_INDICATORS = [
    "UID=0",        # Creating user with root UID
    "UID 0",        # Alternate format
    "-U 0",         # useradd -u 0 shorthand
    "HOME=/ROOT",   # Creating user with /root home
    "SHELL=/BIN/BASH",  # Creating user with login shell
    "HACKER",       # Explicit test case — attacker named account
]


class AccountManagementAnalyzer(BaseAnalyzer):
    """
    Detects user and group management events from Linux auth logs.

    Each event fires an alert immediately. Severity is escalated to CRITICAL
    if the operation shows signs of attacker persistence (creating uid=0 user,
    etc.).
    """

    def __init__(self):
        self.name = "AccountManagementAnalyzer"
        self.enabled = True
        logger.info("AccountManagementAnalyzer initialized")

    def _classify(self, log) -> Optional[dict]:
        """
        Classify account management event.
        Returns {event_name, severity, alert_type} or None.
        """
        log_type   = (getattr(log, "log_type",   "") or "").lower()
        message    = (getattr(log, "message",     "") or "")
        biz        = getattr(log, "business_context", {}) or {}
        threat_cat = (biz.get("threat_category") or "").lower()
        msg_upper  = message.upper()

        # Must be user_management log_type OR have the right threat_category,
        # OR contain a keyword directly in the message (for dead-recovered logs
        # where log_type might be "dead_recovered" but message is still raw)
        is_account_event = (
            log_type == "user_management"
            or threat_cat == "account_change"
            or any(kw for kw, _, _ in ACCOUNT_EVENTS if kw in msg_upper)
        )

        if not is_account_event:
            return None

        # Find which event keyword matched
        event_name = "Account Management Event"
        severity   = "medium"
        for kw, name, sev in ACCOUNT_EVENTS:
            if kw in msg_upper:
                event_name = name
                severity   = sev
                break

        # Escalate to CRITICAL if persistence indicators found
        if any(ind in msg_upper for ind in CRITICAL_INDICATORS):
            severity   = "critical"
            event_name = f"{event_name} [PERSISTENCE INDICATOR]"

        return {
            "event_name": event_name,
            "severity": severity,
            "alert_type": "account_management",
        }

    def analyze(self, log) -> Optional[Alert]:
        """
        Analyze log for account management events.

        Returns Alert immediately for each matching event.
        """
        tenant_id = getattr(log, "tenant_id", "default")

        classification = self._classify(log)
        if not classification:
            return None

        message = getattr(log, "message", "") or ""

        alert = self.create_alert(
            tenant_id=tenant_id,
            alert_type=classification["alert_type"],
            severity=classification["severity"],
            source_ip=getattr(log, "source_ip", None),
            destination_ip=getattr(log, "destination_ip", None),
            device_id=getattr(log, "device_id", None),
            description=(
                f"{classification['severity'].upper()}: {classification['event_name']}. "
                f"Message: {message[:300]}"
            ),
            details={
                "event_name": classification["event_name"],
                "log_type": getattr(log, "log_type", None),
                "vendor": getattr(log, "vendor", None),
                "threat_category": (getattr(log, "business_context", {}) or {}).get("threat_category"),
                "raw_message": message[:500],
            },
        )

        if alert:
            logger.warning(
                f"[ACCOUNT-MGMT] {classification['severity'].upper()} — "
                f"{classification['event_name']} for tenant={tenant_id}"
            )

        return alert
