"""Payload analysis analyzer for detecting web attacks."""

import logging
import re
from typing import Optional

from src.analyzers.base import BaseAnalyzer
from src.models.database import Alert, NormalizedLog

logger = logging.getLogger(__name__)


class PayloadAnalysisAnalyzer(BaseAnalyzer):
    """Detects common web attack patterns in logs and business context."""

    def __init__(self):
        """Initialize payload analysis analyzer."""
        super().__init__("payload_analysis")

        # Simple regex patterns for common attacks
        self.patterns = {
            "sql_injection": [
                r"'.*--",  # SQL comment
                r"'\s*OR\s*.*=.*",  # OR bypass
                r"UNION\s+SELECT",  # UNION based SQLi
                r"SELECT\s+.*\s+FROM\s+",  # Basic SELECT
                r"information_schema",  # Schema discovery
            ],
            "xss": [
                r"<script.*?>.*?</script>",  # Script tags
                r"on\w+\s*=",  # Event handlers
                r"javascript:",  # Javascript protocol
                r"alert\(.*\)",  # Alert function
                r"<.*?>.*?</.*?>",  # Any tag
            ],
            "path_traversal": [
                r"\.\./\.\./",  # Directory traversal
                r"/etc/passwd",  # Sensitive file access
                r"C:\\Windows\\System32",  # Sensitive file access
            ],
            "malware": [
                r"malware",  # Generic malware
                r"cobalt\s*strike",  # Post-exploitation
                r"metasploit",  # Exploit framework
                r"reverse\s*shell",  # Shell pattern
                r"mimikatz",  # Credential dump
                r"trojan",  # Trojan
                r"ransomware",  # Ransomware
            ],
            "c2_communication": [
                r"c2\s*communication",  # Command & Control
                r"beacon",  # Cobalt Strike beacon
                r"shodan",  # Recon tool
                r"censys",  # Recon tool
                r"tor\s*exit",  # TOR network
                r"\.onion",  # Hidden service
            ],
            "data_exfiltration": [
                r"excessive\s*outbound",  # Traffic volume
                r"ftp\s*upload",  # FTP transfer
                r"sensitive\s*data\s*transfer",  # Keyword
                r"large\s*payload\s*detected",  # Anomaly
                r"sftp\s*put",  # File transfer
            ],
            "privilege_escalation": [
                r"sudo\s*failed",  # Sudo failure
                r"root\s*access\s*attempt",  # Admin attempt
                r"unauthorized\s*su",  # SU attempt
                r"privilege\s*elevation",  # Keyword
                r"permission\s*denied\s*for\s*root",  # Root denial
            ],
            "ddos": [
                r"ddos\s*attack\s*detected",  # Generic
                r"syn\s*flood",  # Protocol attack
                r"connection\s*limit\s*exceeded",  # Resource exhaustion
                r"request\s*rate\s*limit",  # Rate limiting
            ],
        }

        # Compile patterns for efficiency
        self.compiled_patterns = {
            attack: [re.compile(p, re.IGNORECASE) for p in p_list] for attack, p_list in self.patterns.items()
        }

    def analyze(self, log: NormalizedLog) -> Optional[Alert]:
        """Analyze log content for attack patterns.

        Args:
            log: NormalizedLog entry to analyze

        Returns:
            Alert if attack pattern detected, None otherwise
        """
        # Data to scan: message and business_context
        items_to_scan = []
        if log.message:
            items_to_scan.append(str(log.message))

        if log.business_context:
            # Flatten business context for easy scanning
            if isinstance(log.business_context, dict):
                items_to_scan.extend([str(v) for v in log.business_context.values()])
            elif isinstance(log.business_context, str):
                items_to_scan.append(log.business_context)

        for content in items_to_scan:
            for attack_type, compiled_list in self.compiled_patterns.items():
                for pattern in compiled_list:
                    if pattern.search(content):
                        # Pattern matched!
                        description = (
                            f"Potential {attack_type.replace('_', ' ').upper()} attack "
                            f"detected in payload. Matched pattern: {pattern.pattern}"
                        )

                        details = {
                            "attack_type": attack_type,
                            "matched_pattern": pattern.pattern,
                            "source_ip": log.source_ip,
                            "destination_ip": log.destination_ip,
                            "content_matched": content[:100] + "..." if len(content) > 100 else content,
                        }

                        return self.create_alert(
                            alert_type="payload_attack",
                            severity="high",
                            source_ip=str(log.source_ip),
                            description=description,
                            details=details,
                            tenant_id=str(log.tenant_id),
                            destination_ip=str(log.destination_ip) if log.destination_ip else None,
                        )

        return None


# Alias for backwards compatibility
PayloadAnalyzer = PayloadAnalysisAnalyzer
