"""Threat intelligence feed management."""

import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any
import csv
from io import StringIO

from src.models.database import ThreatIntelligence
from src.core.database import db_manager
from src.core.config import config

logger = logging.getLogger(__name__)


class ThreatIntelUpdater:
    """Updates threat intelligence indicators from external feeds."""
    
    def __init__(self):
        """Initialize threat intelligence updater."""
        self.feeds = config.threat_intel_feeds
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SIEM-Analyzer/1.0'
        })
    
    def update_all_feeds(self):
        """Update all configured threat intelligence feeds."""
        if not config.threat_intel_enabled:
            logger.info("Threat intelligence is disabled")
            return
        
        logger.info(f"Updating {len(self.feeds)} threat intelligence feeds")
        
        for feed_config in self.feeds:
            try:
                if not feed_config.get('enabled', True):
                    continue
                
                feed_name = feed_config.get('name', 'unknown')
                logger.info(f"Updating feed: {feed_name}")
                
                self.update_feed(feed_config)
                
            except Exception as e:
                logger.error(f"Failed to update feed {feed_name}: {e}")
        
        logger.info("Threat intelligence update completed")
    
    def update_feed(self, feed_config: Dict[str, Any]):
        """Update a single threat intelligence feed.
        
        Args:
            feed_config: Feed configuration dictionary
        """
        feed_name = feed_config.get('name', 'unknown')
        feed_url = feed_config.get('url')
        feed_type = feed_config.get('type', 'ip')
        
        if not feed_url:
            logger.warning(f"No URL configured for feed: {feed_name}")
            return
        
        # Download feed data
        try:
            response = self.session.get(feed_url, timeout=30)
            response.raise_for_status()
            data = response.text
        except requests.RequestException as e:
            logger.error(f"Failed to download feed {feed_name}: {e}")
            return
        
        # Parse feed data
        indicators = self._parse_feed_data(data, feed_type, feed_name)
        
        if not indicators:
            logger.warning(f"No indicators parsed from feed: {feed_name}")
            return
        
        # Store indicators in database
        stored_count = self._store_indicators(indicators, feed_name)
        logger.info(f"Stored {stored_count} indicators from feed: {feed_name}")
    
    def _parse_feed_data(
        self, 
        data: str, 
        feed_type: str,
        feed_name: str
    ) -> List[Dict[str, Any]]:
        """Parse feed data into indicator dictionaries.
        
        Args:
            data: Raw feed data
            feed_type: Type of indicators (ip, domain, hash, url)
            feed_name: Name of the feed
            
        Returns:
            List of indicator dictionaries
        """
        indicators = []
        
        try:
            # Handle CSV format (common for IP blocklists)
            if feed_type == 'ip':
                lines = data.strip().split('\n')
                for line in lines:
                    # Skip comments and empty lines
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try to extract IP (handle CSV or plain text)
                    parts = line.split(',')
                    ip_address = parts[0].strip()
                    
                    # Basic IP validation
                    if self._is_valid_ip(ip_address):
                        indicators.append({
                            'type': 'ip',
                            'value': ip_address,
                            'threat_type': 'malicious',
                            'confidence': 0.8,
                            'description': f'Malicious IP from {feed_name}'
                        })
        
        except Exception as e:
            logger.error(f"Error parsing feed data: {e}")
        
        return indicators
    
    def _is_valid_ip(self, ip_string: str) -> bool:
        """Basic IP address validation.
        
        Args:
            ip_string: String to validate
            
        Returns:
            True if valid IP, False otherwise
        """
        parts = ip_string.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def _store_indicators(
        self, 
        indicators: List[Dict[str, Any]], 
        source: str
    ) -> int:
        """Store indicators in database.
        
        Args:
            indicators: List of indicator dictionaries
            source: Feed source name
            
        Returns:
            Number of indicators stored
        """
        stored_count = 0
        
        try:
            with db_manager.session_scope() as session:
                for indicator_data in indicators:
                    indicator_value = indicator_data['value']
                    
                    # Check if indicator already exists
                    existing = session.query(ThreatIntelligence).filter(
                        ThreatIntelligence.indicator_value == indicator_value
                    ).first()
                    
                    if existing:
                        # Update existing indicator
                        existing.last_seen = datetime.utcnow()
                        existing.is_active = True
                        existing.source = source
                    else:
                        # Create new indicator
                        indicator = ThreatIntelligence(
                            indicator_type=indicator_data['type'],
                            indicator_value=indicator_value,
                            threat_type=indicator_data.get('threat_type', 'unknown'),
                            confidence=indicator_data.get('confidence', 0.5),
                            source=source,
                            description=indicator_data.get('description', ''),
                            is_active=True
                        )
                        session.add(indicator)
                    
                    stored_count += 1
                
                session.commit()
        
        except Exception as e:
            logger.error(f"Error storing indicators: {e}")
        
        return stored_count
    
    def deactivate_old_indicators(self, days: int = 30):
        """Deactivate indicators not seen recently.
        
        Args:
            days: Number of days of inactivity before deactivation
        """
        try:
            threshold_date = datetime.utcnow() - timedelta(days=days)
            
            with db_manager.session_scope() as session:
                count = session.query(ThreatIntelligence).filter(
                    ThreatIntelligence.last_seen < threshold_date,
                    ThreatIntelligence.is_active == True
                ).update({'is_active': False})
                
                session.commit()
                logger.info(f"Deactivated {count} old threat indicators")
        
        except Exception as e:
            logger.error(f"Error deactivating old indicators: {e}")
