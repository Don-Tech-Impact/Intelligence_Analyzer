"""Brute force attack detection analyzer."""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict
from collections import defaultdict

from src.analyzers.base import BaseAnalyzer
from src.models.database import Log, Alert
from src.core.config import config
from src.core.database import db_manager

logger = logging.getLogger(__name__)


class BruteForceAnalyzer(BaseAnalyzer):
    """Detects brute force authentication attempts."""
    
    def __init__(self):
        """Initialize brute force analyzer."""
        super().__init__('brute_force')
        self.threshold = config.brute_force_threshold
        self.time_window = config.brute_force_time_window
        
        # Cache for tracking failed attempts (source_ip -> count)
        self._attempt_cache: Dict[str, list] = defaultdict(list)
    
    def analyze(self, log: Log) -> Optional[Alert]:
        """Analyze log for brute force patterns.
        
        Args:
            log: Log entry to analyze
            
        Returns:
            Alert if brute force detected, None otherwise
        """
        # Only analyze authentication-related logs with failures
        if not self._is_auth_failure(log):
            return None
        
        source_ip = log.source_ip
        if not source_ip:
            return None
        
        # Get recent failed attempts from database
        failed_attempts = self._get_recent_failed_attempts(
            source_ip, 
            log.tenant_id, 
            log.timestamp
        )
        
        if failed_attempts >= self.threshold:
            # Brute force detected
            description = (
                f"Brute force attack detected from {source_ip}. "
                f"{failed_attempts} failed authentication attempts in "
                f"{self.time_window} seconds."
            )
            
            details = {
                'source_ip': source_ip,
                'failed_attempts': failed_attempts,
                'time_window': self.time_window,
                'threshold': self.threshold,
                'destination_ip': log.destination_ip,
                'destination_port': log.destination_port
            }
            
            # Determine severity based on number of attempts
            if failed_attempts > self.threshold * 3:
                severity = 'critical'
            elif failed_attempts > self.threshold * 2:
                severity = 'high'
            else:
                severity = 'medium'
            
            return self.create_alert(
                alert_type='brute_force',
                severity=severity,
                source_ip=source_ip,
                description=description,
                details=details,
                tenant_id=log.tenant_id,
                destination_ip=log.destination_ip
            )
        
        return None
    
    def _is_auth_failure(self, log: Log) -> bool:
        """Check if log represents an authentication failure.
        
        Args:
            log: Log entry
            
        Returns:
            True if authentication failure, False otherwise
        """
        # Check log type
        if log.log_type and 'auth' in log.log_type.lower():
            # Check action or message for failure indicators
            failure_indicators = ['failed', 'failure', 'denied', 'invalid', 'reject']
            
            if log.action:
                if any(indicator in log.action.lower() for indicator in failure_indicators):
                    return True
            
            if log.message:
                if any(indicator in log.message.lower() for indicator in failure_indicators):
                    return True
        
        return False
    
    def _get_recent_failed_attempts(
        self, 
        source_ip: str, 
        tenant_id: str, 
        timestamp: datetime
    ) -> int:
        """Get count of recent failed authentication attempts.
        
        Args:
            source_ip: Source IP address
            tenant_id: Tenant identifier
            timestamp: Current timestamp
            
        Returns:
            Number of failed attempts in time window
        """
        try:
            time_threshold = timestamp - timedelta(seconds=self.time_window)
            
            with db_manager.session_scope() as session:
                count = session.query(Log).filter(
                    Log.tenant_id == tenant_id,
                    Log.source_ip == source_ip,
                    Log.timestamp >= time_threshold,
                    Log.timestamp <= timestamp,
                    Log.log_type.like('%auth%')
                ).count()
                
                return count
        except Exception as e:
            logger.error(f"Error querying failed attempts: {e}")
            return 0
