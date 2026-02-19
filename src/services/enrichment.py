"""Enrichment service for Intelligence Analyzer."""

import logging
from typing import Dict, Any, Optional
from src.core.database import db_manager
from src.models.database import ThreatIntelligence

logger = logging.getLogger(__name__)

class EnrichmentService:
    """Service to enrich logs with intelligence and metadata."""

    @staticmethod
    def enrich(normalized_log) -> None:
        """
        Enriches a NormalizedLog instance with additional intelligence.
        
        Args:
            normalized_log: The NormalizedLog SQLAlchemy instance to enrich.
        """
        try:
            # 1. Threat Intel Enrichment
            EnrichmentService._check_threat_intel(normalized_log)
            
            # 2. GeoIP Enrichment (Mocked for Demo)
            EnrichmentService._add_geoip_metadata(normalized_log)
            
            # 3. Contextual Scoring
            EnrichmentService._calculate_threat_score(normalized_log)
            
        except Exception as e:
            logger.error(f"Enrichment failed: {e}")

    @staticmethod
    def _check_threat_intel(log) -> None:
        """Check source and destination IPs against known threat intelligence."""
        with db_manager.session_scope() as session:
            # Check source IP
            intel = session.query(ThreatIntelligence).filter(
                ThreatIntelligence.indicator_value == log.source_ip,
                ThreatIntelligence.is_active == True
            ).first()
            
            if intel:
                log.severity = 'critical'
                if not log.business_context:
                    log.business_context = {}
                log.business_context['threat_intel_match'] = {
                    'type': intel.threat_type,
                    'confidence': intel.confidence,
                    'description': intel.description
                }

    @staticmethod
    def _add_geoip_metadata(log) -> None:
        """Add mocked GeoIP metadata."""
        # In a real system, we'd use MaxMind or an API here.
        if not log.business_context:
            log.business_context = {}
            
        # Mock logic based on IP range
        ip_prefix = log.source_ip.split('.')[0] if log.source_ip and '.' in log.source_ip else "0"
        
        geo_map = {
            "10": {"country": "Internal", "code": "LAN"},
            "192": {"country": "Local", "code": "LAN"},
            "172": {"country": "Private", "code": "LAN"},
            "8": {"country": "USA", "code": "US"},
            "1": {"country": "Global", "code": "GL"}
        }
        
        log.business_context['geoip'] = geo_map.get(ip_prefix, {"country": "Unknown", "code": "XX"})

    @staticmethod
    def _calculate_threat_score(log) -> None:
        """Calculate a numerical threat score (0-100)."""
        score = 10 # Baseline
        
        if log.severity == 'critical': score += 50
        elif log.severity == 'high': score += 30
        elif log.severity == 'medium': score += 15
        
        if log.business_context and log.business_context.get('threat_intel_match'):
            score += 20
            
        if not log.business_context:
            log.business_context = {}
        log.business_context['threat_score'] = min(score, 100)
