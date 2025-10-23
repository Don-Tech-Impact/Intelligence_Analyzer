"""Base analyzer class for threat detection."""

from abc import ABC, abstractmethod
from typing import List, Optional
import logging
from datetime import datetime

from src.models.database import Log, Alert
from src.core.database import db_manager

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Base class for all threat analyzers."""
    
    def __init__(self, name: str):
        """Initialize analyzer.
        
        Args:
            name: Analyzer name
        """
        self.name = name
        self.enabled = True
    
    @abstractmethod
    def analyze(self, log: Log) -> Optional[Alert]:
        """Analyze a log entry for threats.
        
        Args:
            log: Log entry to analyze
            
        Returns:
            Alert object if threat detected, None otherwise
        """
        pass
    
    def create_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str,
        description: str,
        details: dict,
        tenant_id: str = 'default',
        destination_ip: Optional[str] = None
    ) -> Optional[Alert]:
        """Create and store an alert.
        
        Args:
            alert_type: Type of alert
            severity: Alert severity (low, medium, high, critical)
            source_ip: Source IP address
            description: Alert description
            details: Additional alert details
            tenant_id: Tenant identifier
            destination_ip: Optional destination IP
            
        Returns:
            Created Alert object or None if creation fails
        """
        try:
            with db_manager.session_scope() as session:
                alert = Alert(
                    tenant_id=tenant_id,
                    alert_type=alert_type,
                    severity=severity,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    description=description,
                    details=details,
                    status='open',
                    notified=False
                )
                session.add(alert)
                session.commit()
                logger.info(f"Created {severity} alert: {alert_type} from {source_ip}")
                return alert
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None
    
    def enable(self):
        """Enable this analyzer."""
        self.enabled = True
        logger.info(f"Analyzer {self.name} enabled")
    
    def disable(self):
        """Disable this analyzer."""
        self.enabled = False
        logger.info(f"Analyzer {self.name} disabled")


class AnalyzerManager:
    """Manages all threat analyzers."""
    
    def __init__(self):
        """Initialize analyzer manager."""
        self.analyzers: List[BaseAnalyzer] = []
    
    def register(self, analyzer: BaseAnalyzer):
        """Register an analyzer.
        
        Args:
            analyzer: Analyzer instance to register
        """
        self.analyzers.append(analyzer)
        logger.info(f"Registered analyzer: {analyzer.name}")
    
    def analyze_log(self, log: Log) -> List[Alert]:
        """Run all analyzers on a log entry.
        
        Args:
            log: Log entry to analyze
            
        Returns:
            List of generated alerts
        """
        alerts = []
        for analyzer in self.analyzers:
            if not analyzer.enabled:
                continue
            
            try:
                alert = analyzer.analyze(log)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Error in analyzer {analyzer.name}: {e}", exc_info=True)
        
        return alerts
    
    def get_analyzer(self, name: str) -> Optional[BaseAnalyzer]:
        """Get analyzer by name.
        
        Args:
            name: Analyzer name
            
        Returns:
            Analyzer instance or None if not found
        """
        for analyzer in self.analyzers:
            if analyzer.name == name:
                return analyzer
        return None


# Global analyzer manager instance
analyzer_manager = AnalyzerManager()
