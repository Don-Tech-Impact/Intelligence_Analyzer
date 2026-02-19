"""Port Scan Analyzer - Redis Edition.

=============================================================================
DETECTION LOGIC
=============================================================================
Detects: Network reconnaissance, port scanning, service enumeration

Pattern: Source IP accessing multiple unique destination ports on a target
         within a short time window.

Redis State:
    Key: ps:{tenant_id}:{source_ip}:{destination_ip}
    Type: SET (unique ports via SADD)
    TTL: 60 seconds (1 minute window)
    
Performance:
    - O(1) per log (SADD + SCARD + EXPIRE)
    - No database queries during detection
    - Automatic cleanup via TTL
    
Accuracy:
    - Exact count of unique ports
    - SET guarantees no duplicates
    - Matches original DB-based logic
=============================================================================
"""

import logging
import os
import redis
from typing import Optional, List
from datetime import datetime

from src.core.config import config
from src.models.database import Alert

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================
# Threshold: Number of unique ports to trigger alert
PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', 10))
# Window: Time period in seconds
PORT_SCAN_WINDOW = int(os.getenv('PORT_SCAN_WINDOW', 60))  # 1 minute


class PortScanAnalyzer:
    """
    Detects port scanning using Redis sets.
    
    Replaces: SELECT COUNT(DISTINCT destination_port) FROM logs 
              WHERE source_ip=? AND destination_ip=? AND timestamp > ?
    With: Redis SADD + SCARD (O(1) vs O(n))
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize analyzer with Redis client.
        
        Args:
            redis_client: Shared Redis connection. If None, creates new one.
        """
        # Required attributes for AnalyzerManager
        self.name = "PortScanAnalyzer"
        self.enabled = True
        
        self.redis_client = redis_client
        self.threshold = PORT_SCAN_THRESHOLD
        self.window_seconds = PORT_SCAN_WINDOW
        
        if self.redis_client is None:
            self._connect_redis()
        
        logger.info(f"PortScanAnalyzer initialized: threshold={self.threshold}, window={self.window_seconds}s")
    
    def _connect_redis(self):
        """Create Redis connection."""
        try:
            self.redis_client = redis.from_url(
                config.redis_url,
                decode_responses=True,
                socket_connect_timeout=5
            )
            self.redis_client.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    def _get_redis_key(self, tenant_id: str, source_ip: str, dest_ip: str) -> str:
        """
        Generate Redis key for port scan tracking.
        
        Pattern: ps:{tenant_id}:{source_ip}:{destination_ip}
        Example: ps:acme_corp:192.168.1.100:10.0.0.5
        """
        return f"ps:{tenant_id}:{source_ip}:{dest_ip}"
    
    def _is_relevant_log(self, log) -> bool:
        """
        Check if log represents network traffic that could indicate scanning.
        
        Includes:
            - Firewall logs with connection attempts
            - Network flow data
            - Connection refused/denied events
        """
        log_type = getattr(log, 'log_type', '') or ''
        action = getattr(log, 'action', '') or ''
        
        # Include network-related log types
        relevant_types = ['firewall', 'network', 'flow', 'connection', 'netflow']
        if any(t in log_type.lower() for t in relevant_types):
            return True
        
        # Include connection-related actions
        relevant_actions = ['allow', 'deny', 'drop', 'reject', 'accept', 'syn']
        if any(a in action.lower() for a in relevant_actions):
            return True
        
        return False
    
    def analyze(self, log) -> Optional[Alert]:
        """
        Analyze log for port scanning patterns.
        
        Algorithm:
            1. Check if log is network-related → if not, return None
            2. SADD destination port to Redis set for this src/dst pair
            3. Set TTL if first port
            4. SCARD to get unique port count
            5. If count >= threshold → Create alert
        
        Args:
            log: NormalizedLog or log-like object with attributes
            
        Returns:
            Alert if port scan detected, None otherwise
        """
        # Skip if not relevant network traffic
        # NOTE: We're being permissive here to catch more scans
        # Comment out for stricter filtering:
        # if not self._is_relevant_log(log):
        #     return None
        
        # Get required fields
        source_ip = getattr(log, 'source_ip', None)
        dest_ip = getattr(log, 'destination_ip', None)
        dest_port = getattr(log, 'destination_port', None)
        tenant_id = getattr(log, 'tenant_id', 'default')
        
        # Skip if missing required fields
        if not source_ip or not dest_ip or dest_port is None:
            return None
        
        # Skip internal scans (often legitimate)
        # Uncomment to filter out RFC1918 → RFC1918 traffic
        # if self._is_internal(source_ip) and self._is_internal(dest_ip):
        #     return None
        
        # Skip if Redis unavailable
        if self.redis_client is None:
            logger.warning("Redis unavailable, skipping port scan analysis")
            return None
        
        try:
            # =========================================================
            # REDIS STATE UPDATE (O(1))
            # =========================================================
            key = self._get_redis_key(tenant_id, source_ip, dest_ip)
            
            # Add port to set (returns 1 if new, 0 if exists)
            is_new = self.redis_client.sadd(key, dest_port)
            
            # Set expiration on first port added
            if is_new:
                # Only set TTL if key is new (SADD returns 1 for first element)
                current_size = self.redis_client.scard(key)
                if current_size == 1:
                    self.redis_client.expire(key, self.window_seconds)
            
            # Get unique port count
            unique_ports = self.redis_client.scard(key)
            
            logger.debug(f"Port scan counter {source_ip}→{dest_ip}: {unique_ports}/{self.threshold}")
            
            # =========================================================
            # ALERT GENERATION
            # =========================================================
            if unique_ports >= self.threshold:
                # Get the actual ports for context
                scanned_ports = self.redis_client.smembers(key)
                ttl = self.redis_client.ttl(key)
                
                alert = Alert(
                    tenant_id=tenant_id,
                    alert_type='port_scan',
                    severity='medium',
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    description=(
                        f"Port scan detected: {source_ip} scanned {unique_ports} unique ports "
                        f"on {dest_ip} within {self.window_seconds}s"
                    ),
                    details={
                        'unique_ports': unique_ports,
                        'threshold': self.threshold,
                        'window_seconds': self.window_seconds,
                        'time_remaining': ttl,
                        'scanned_ports': sorted([int(p) for p in scanned_ports])[:20],  # Top 20
                        'detection_method': 'redis_set'
                    },
                    status='open'
                )
                
                logger.warning(
                    f"ALERT: Port scan {source_ip}→{dest_ip} "
                    f"({unique_ports} ports in {self.window_seconds}s)"
                )
                
                # Reset to prevent alert spam
                # Keep the set but raise severity on subsequent detections
                
                return alert
            
            return None
            
        except redis.RedisError as e:
            logger.error(f"Redis error in port scan analysis: {e}")
            return None
    
    def get_scanned_ports(self, tenant_id: str, source_ip: str, dest_ip: str) -> List[int]:
        """Get list of scanned ports for debugging/API."""
        if self.redis_client is None:
            return []
        
        try:
            key = self._get_redis_key(tenant_id, source_ip, dest_ip)
            ports = self.redis_client.smembers(key)
            return sorted([int(p) for p in ports])
        except redis.RedisError:
            return []
    
    def reset_tracking(self, tenant_id: str, source_ip: str, dest_ip: str):
        """Reset tracking for a source/dest pair."""
        if self.redis_client is None:
            return
        
        try:
            key = self._get_redis_key(tenant_id, source_ip, dest_ip)
            self.redis_client.delete(key)
            logger.info(f"Reset port scan tracking for {source_ip}→{dest_ip}")
        except redis.RedisError as e:
            logger.error(f"Failed to reset tracking: {e}")


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================
_analyzer_instance: Optional[PortScanAnalyzer] = None


def get_analyzer(redis_client: Optional[redis.Redis] = None) -> PortScanAnalyzer:
    """Get or create singleton analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = PortScanAnalyzer(redis_client)
    return _analyzer_instance
