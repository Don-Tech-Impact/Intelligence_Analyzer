"""Privilege Escalation Analyzer.

=============================================================================
DETECTION LOGIC
=============================================================================
Detects: sudo abuse, su failures, root SSH logins, dangerous command execution

Each event individually triggers an alert (no threshold counting needed).
Severity is content-driven — dangerous commands get CRITICAL, failures get HIGH.

Detection sources:
    - log_type: "priv_escalation" (set by LogAdapter._parse_syslog_auth)
    - business_context.threat_category: "dangerous_sudo", "sudo_failure", etc.
    - Raw message keywords (fallback)
=============================================================================
"""

import logging
from typing import Optional

from src.analyzers.base import BaseAnalyzer
from src.models.database import Alert

logger = logging.getLogger(__name__)

# Commands in sudo logs that indicate privilege escalation / system compromise
DANGEROUS_COMMANDS = [
    "/etc/shadow",       # Reading password hashes
    "/bin/bash",         # Spawning root shell
    "/bin/sh",           # Spawning root shell (sh variant)
    "/bin/su",           # Switching user from sudo
    "chmod 777",         # World-writable permission
    "useradd -o",        # Creating user with overridden UID
    "useradd -u 0",      # Creating user with root UID
    "chpasswd",          # Bulk password change
    "visudo",            # Editing sudoers file
    "/etc/passwd",       # Modifying user database
    "/etc/sudoers",      # Backdoor sudoers
    "base64",            # Obfuscated payload execution
    "wget",              # Downloading files as root
    "curl",              # Downloading files as root
    "/dev/tcp",          # Reverse shell pattern
    "openssl passwd",    # Generating password hashes
]


class PrivilegeEscalationAnalyzer(BaseAnalyzer):
    """
    Detects privilege escalation events from Linux auth logs.

    Fires on:
    - Dangerous sudo commands (critical)
    - Root SSH login (high)
    - Failed sudo / su (high)
    - General sudo root usage (medium)
    """

    def __init__(self):
        self.name = "PrivilegeEscalationAnalyzer"
        self.enabled = True
        logger.info("PrivilegeEscalationAnalyzer initialized")

    def _classify(self, log) -> Optional[dict]:
        """
        Determine if this log is a privilege escalation event and return
        classification dict: {severity, alert_type, description} or None.
        """
        log_type   = (getattr(log, "log_type",   "") or "").lower()
        action     = (getattr(log, "action",      "") or "").lower()
        message    = (getattr(log, "message",     "") or "")
        biz        = getattr(log, "business_context", {}) or {}
        threat_cat = (biz.get("threat_category") or "").lower()
        severity   = (getattr(log, "severity",    "") or "").lower()
        msg_upper  = message.upper()
        source_ip  = getattr(log, "source_ip", None)

        # ── 1. Dangerous sudo command (CRITICAL) ─────────────────────────────
        if threat_cat == "dangerous_sudo" or (
            log_type == "priv_escalation"
            and any(d.upper() in msg_upper for d in DANGEROUS_COMMANDS)
        ):
            cmd = next((d for d in DANGEROUS_COMMANDS if d.upper() in msg_upper), "unknown")
            return {
                "severity": "critical",
                "alert_type": "privilege_escalation",
                "description": (
                    f"CRITICAL: Dangerous sudo command executed as root: '{cmd}'. "
                    f"Message: {message[:200]}"
                ),
            }

        # ── 2. Root login via SSH (HIGH) ──────────────────────────────────────
        if threat_cat == "root_login" or (
            log_type == "auth_success"
            and ("FOR ROOT" in msg_upper or " ROOT " in msg_upper)
            and "ACCEPTED" in msg_upper
        ):
            return {
                "severity": "high",
                "alert_type": "privilege_escalation",
                "description": (
                    f"HIGH: Direct root login via SSH from {source_ip}. "
                    "Root direct login bypasses audit trail — use sudo instead."
                ),
            }

        # ── 3. Failed sudo / su escalation attempt (HIGH) ────────────────────
        if threat_cat in ("sudo_failure", "su_failure") or (
            log_type == "priv_escalation" and action == "deny"
        ):
            return {
                "severity": "high",
                "alert_type": "privilege_escalation",
                "description": (
                    f"HIGH: Failed privilege escalation attempt. "
                    f"Message: {message[:200]}"
                ),
            }

        # ── 4. General sudo root execution (MEDIUM) — only if already high ───
        # Avoid flooding — only alert if LogAdapter already set severity >= high
        if log_type == "priv_escalation" and severity in ("high", "critical"):
            return {
                "severity": "medium",
                "alert_type": "privilege_escalation",
                "description": (
                    f"MEDIUM: Sudo root command executed. "
                    f"Message: {message[:200]}"
                ),
            }

        return None

    def analyze(self, log) -> Optional[Alert]:
        """
        Analyze log for privilege escalation.

        Returns Alert immediately on each matching event (no threshold).
        """
        tenant_id = getattr(log, "tenant_id", "default")

        classification = self._classify(log)
        if not classification:
            return None

        alert = self.create_alert(
            tenant_id=tenant_id,
            alert_type=classification["alert_type"],
            severity=classification["severity"],
            source_ip=getattr(log, "source_ip", None),
            destination_ip=getattr(log, "destination_ip", None),
            device_id=getattr(log, "device_id", None),
            description=classification["description"],
            details={
                "log_type": getattr(log, "log_type", None),
                "action": getattr(log, "action", None),
                "vendor": getattr(log, "vendor", None),
                "threat_category": (getattr(log, "business_context", {}) or {}).get("threat_category"),
                "raw_message": (getattr(log, "message", "") or "")[:500],
            },
        )

        if alert:
            logger.warning(
                f"[PRIV-ESC] {classification['severity'].upper()} alert for "
                f"tenant={tenant_id}, type={classification['alert_type']}"
            )

        return alert
