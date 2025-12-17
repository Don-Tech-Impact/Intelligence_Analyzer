"""Threat intelligence analyzer."""

import logging
from typing import Optional
from datetime import datetime

from src.analyzers.base import BaseAnalyzer
from src.models.database import NormalizedLog, Alert, ThreatIntelligence
from src.core.database import db_manager

logger = logging.getLogger(__name__)


class ThreatIntelAnalyzer(BaseAnalyzer):
    """Matches log entries against threat intelligence feeds."""
    
    def __init__(self):
        """Initialize threat intelligence analyzer."""
        super().__init__('threat_intel')
    
    def analyze(self, log: NormalizedLog) -> Optional[Alert]:
        """Analyze log against threat intelligence indicators.
        
        Args:
            log: NormalizedLog entry to analyze
            
        Returns:
            Alert if threat indicator matched, None otherwise
        """
        # Check source IP
        if log.source_ip:
            threat = self._check_ip(log.source_ip)
            if threat:
                return self._create_threat_alert(log, threat, 'source')
        
        # Check destination IP
        if log.destination_ip:
            threat = self._check_ip(log.destination_ip)
            if threat:
                return self._create_threat_alert(log, threat, 'destination')
        
        return None
    
    def _check_ip(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check if IP is in threat intelligence database.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            ThreatIntelligence object if found, None otherwise
        """
        try:
            with db_manager.session_scope() as session:
                threat = session.query(ThreatIntelligence).filter(
                    ThreatIntelligence.indicator_type == 'ip',
                    ThreatIntelligence.indicator_value == ip_address,
                    ThreatIntelligence.is_active == True
                ).first()
                
                if threat:
                    # Update last_seen timestamp
                    threat.last_seen = datetime.utcnow()
                    session.commit()
                
                return threat
        except Exception as e:
            logger.error(f"Error checking threat intelligence: {e}")
            return None
    
    def _create_threat_alert(
        self,
        log: NormalizedLog,
        threat: ThreatIntelligence,
        direction: str
    ) -> Optional[Alert]:
        """Create alert for threat intelligence match.
        
        Args:
            log: NormalizedLog entry
            threat: Matched threat intelligence
            direction: 'source' or 'destination'
            
        Returns:
            Created Alert object
        """
        ip_address = log.source_ip if direction == 'source' else log.destination_ip
        
        description = (
            f"Threat intelligence match: {ip_address} ({direction} IP) "
            f"is known {threat.threat_type}. Source: {threat.source}"
        )
        
        details = {
            'matched_ip': ip_address,
            'direction': direction,
            'threat_type': threat.threat_type,
            'confidence': threat.confidence,
            'source': threat.source,
            'indicator_description': threat.description,
            'first_seen': threat.first_seen.isoformat() if threat.first_seen else None,
            'last_seen': threat.last_seen.isoformat() if threat.last_seen else None
        }
        
        # Determine severity based on confidence and threat type
        if threat.confidence and threat.confidence > 0.8:
            severity = 'high'
        elif threat.confidence and threat.confidence > 0.5:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Escalate for certain threat types
        if threat.threat_type and any(t in threat.threat_type.lower() 
                                      for t in ['botnet', 'c2', 'command']):
            severity = 'critical'
        
        return self.create_alert(
            alert_type='threat_intel',
            severity=severity,
            source_ip=log.source_ip,
            description=description,
            details=details,
            tenant_id=log.tenant_id,
            destination_ip=log.destination_ip
        )
