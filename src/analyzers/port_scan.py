"""Port scanning detection analyzer."""

import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import func

from src.analyzers.base import BaseAnalyzer
from src.models.database import Log, Alert
from src.core.config import config
from src.core.database import db_manager

logger = logging.getLogger(__name__)


class PortScanAnalyzer(BaseAnalyzer):
    """Detects port scanning activities."""
    
    def __init__(self):
        """Initialize port scan analyzer."""
        super().__init__('port_scan')
        self.threshold = config.port_scan_threshold
        self.time_window = config.port_scan_time_window
    
    def analyze(self, log: Log) -> Optional[Alert]:
        """Analyze log for port scanning patterns.
        
        Args:
            log: Log entry to analyze
            
        Returns:
            Alert if port scan detected, None otherwise
        """
        source_ip = log.source_ip
        destination_ip = log.destination_ip
        
        if not source_ip or not destination_ip:
            return None
        
        # Get count of unique destination ports from this source
        unique_ports = self._get_unique_ports_accessed(
            source_ip,
            destination_ip,
            log.tenant_id,
            log.timestamp
        )
        
        if unique_ports >= self.threshold:
            # Port scan detected
            description = (
                f"Port scan detected from {source_ip} to {destination_ip}. "
                f"{unique_ports} unique ports accessed in {self.time_window} seconds."
            )
            
            details = {
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'unique_ports': unique_ports,
                'time_window': self.time_window,
                'threshold': self.threshold
            }
            
            # Determine severity based on number of ports
            if unique_ports > self.threshold * 5:
                severity = 'high'
            elif unique_ports > self.threshold * 2:
                severity = 'medium'
            else:
                severity = 'low'
            
            return self.create_alert(
                alert_type='port_scan',
                severity=severity,
                source_ip=source_ip,
                description=description,
                details=details,
                tenant_id=log.tenant_id,
                destination_ip=destination_ip
            )
        
        return None
    
    def _get_unique_ports_accessed(
        self,
        source_ip: str,
        destination_ip: str,
        tenant_id: str,
        timestamp: datetime
    ) -> int:
        """Get count of unique destination ports accessed.
        
        Args:
            source_ip: Source IP address
            destination_ip: Destination IP address
            tenant_id: Tenant identifier
            timestamp: Current timestamp
            
        Returns:
            Number of unique ports accessed
        """
        try:
            time_threshold = timestamp - timedelta(seconds=self.time_window)
            
            with db_manager.session_scope() as session:
                # Count distinct destination ports
                count = session.query(
                    func.count(func.distinct(Log.destination_port))
                ).filter(
                    Log.tenant_id == tenant_id,
                    Log.source_ip == source_ip,
                    Log.destination_ip == destination_ip,
                    Log.timestamp >= time_threshold,
                    Log.timestamp <= timestamp,
                    Log.destination_port.isnot(None)
                ).scalar()
                
                return count or 0
        except Exception as e:
            logger.error(f"Error querying unique ports: {e}")
            return 0
