"""Brute Force Attack Analyzer - Redis Edition.

=============================================================================
DETECTION LOGIC
=============================================================================
Detects: Password guessing, credential stuffing, SSH brute force

Pattern: Multiple failed authentication attempts from same source IP
         within a short time window.

Redis State:
    Key: bf:{tenant_id}:{source_ip}
    Type: STRING (counter via INCR)
    TTL: 300 seconds (5 minute window)
    
Performance:
    - O(1) per log (INCR + EXPIRE)
    - No database queries during detection
    - Automatic cleanup via TTL
    
Accuracy:
    - Exact count (not approximate)
    - Window resets on first occurrence
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
# Threshold: Number of failed attempts to trigger alert
BRUTE_FORCE_THRESHOLD = int(os.getenv('BRUTE_FORCE_THRESHOLD', 5))
# Window: Time period in seconds
BRUTE_FORCE_WINDOW = int(os.getenv('BRUTE_FORCE_WINDOW', 300))  # 5 minutes


class BruteForceAnalyzer:
    """
    Detects brute force attacks using Redis counters.
    
    Replaces: SELECT COUNT(*) FROM logs WHERE source_ip=? AND timestamp > ?
    With: Redis INCR + EXPIRE (O(1) vs O(n))
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize analyzer with Redis client.
        
        Args:
            redis_client: Shared Redis connection. If None, creates new one.
        """
        # Required attributes for AnalyzerManager
        self.name = "BruteForceAnalyzer"
        self.enabled = True
        
        self.redis_client = redis_client
        self.threshold = BRUTE_FORCE_THRESHOLD
        self.window_seconds = BRUTE_FORCE_WINDOW
        
        # Connect to Redis if not provided
        if self.redis_client is None:
            self._connect_redis()
        
        logger.info(f"BruteForceAnalyzer initialized: threshold={self.threshold}, window={self.window_seconds}s")
    
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
    
    def _is_auth_failure(self, log) -> bool:
        """
        Check if log represents a failed authentication attempt.
        
        Matches:
            - log_type containing 'auth' with action 'failed'/'denied'
            - SSH failures (port 22, action failed)
            - Firewall auth denials
        """
        log_type = getattr(log, 'log_type', '') or ''
        action = getattr(log, 'action', '') or ''
        dest_port = getattr(log, 'destination_port', None)
        message = getattr(log, 'message', '') or ''
        
        # Check log type + action
        if 'auth' in log_type.lower():
            if action.lower() in ('failed', 'denied', 'failure', 'rejected'):
                return True
        
        # Check SSH failures
        if dest_port == 22 and action.lower() in ('failed', 'denied', 'rejected'):
            return True
        
        # Check message for auth failure indicators
        auth_failure_keywords = [
            'authentication failed',
            'login failed',
            'invalid password',
            'access denied',
            'unauthorized',
            'failed password'
        ]
        message_lower = message.lower()
        if any(kw in message_lower for kw in auth_failure_keywords):
            return True
        
        return False
    
    def _get_redis_key(self, tenant_id: str, source_ip: str) -> str:
        """
        Generate Redis key for brute force counter.
        
        Pattern: bf:{tenant_id}:{source_ip}
        Example: bf:acme_corp:192.168.1.100
        """
        return f"bf:{tenant_id}:{source_ip}"
    
    def analyze(self, log) -> Optional[Alert]:
        """
        Analyze log for brute force attack patterns.
        
        Algorithm:
            1. Check if log is auth failure → if not, return None
            2. INCR Redis counter for this IP
            3. Set TTL if first occurrence
            4. If count >= threshold → Create alert
        
        Args:
            log: NormalizedLog or log-like object with attributes
            
        Returns:
            Alert if brute force detected, None otherwise
        """
        # Skip if not auth failure
        if not self._is_auth_failure(log):
            return None
        
        # Skip if missing required fields
        source_ip = getattr(log, 'source_ip', None)
        tenant_id = getattr(log, 'tenant_id', 'default')
        
        if not source_ip:
            return None
        
        # Skip if Redis unavailable
        if self.redis_client is None:
            logger.warning("Redis unavailable, skipping brute force analysis")
            return None
        
        try:
            # =========================================================
            # REDIS STATE UPDATE (O(1))
            # =========================================================
            key = self._get_redis_key(tenant_id, source_ip)
            
            # Increment counter
            count = self.redis_client.incr(key)
            
            # Set expiration on first increment
            if count == 1:
                self.redis_client.expire(key, self.window_seconds)
            
            logger.debug(f"Brute force counter for {source_ip}: {count}/{self.threshold}")
            
            # =========================================================
            # ALERT GENERATION
            # =========================================================
            if count >= self.threshold:
                # Get remaining TTL for context
                ttl = self.redis_client.ttl(key)
                
                alert = Alert(
                    tenant_id=tenant_id,
                    alert_type='brute_force',
                    severity='high',
                    source_ip=source_ip,
                    destination_ip=getattr(log, 'destination_ip', None),
                    description=(
                        f"Brute force attack detected: {count} failed authentication attempts "
                        f"from {source_ip} in the last {self.window_seconds - ttl} seconds"
                    ),
                    details={
                        'attempt_count': count,
                        'threshold': self.threshold,
                        'window_seconds': self.window_seconds,
                        'time_remaining': ttl,
                        'detection_method': 'redis_counter',
                        'last_log_type': getattr(log, 'log_type', None),
                        'last_action': getattr(log, 'action', None)
                    },
                    status='open'
                )
                
                logger.warning(
                    f"ALERT: Brute force from {source_ip} "
                    f"({count} attempts in {self.window_seconds}s window)"
                )
                
                # Reset counter after alert to prevent spam
                # Comment out if you want continued counting
                # self.redis_client.delete(key)
                
                return alert
            
            return None
            
        except redis.RedisError as e:
            logger.error(f"Redis error in brute force analysis: {e}")
            return None
    
    def get_attempt_count(self, tenant_id: str, source_ip: str) -> int:
        """Get current attempt count for an IP (for debugging/API)."""
        if self.redis_client is None:
            return 0
        
        try:
            key = self._get_redis_key(tenant_id, source_ip)
            count = self.redis_client.get(key)
            return int(count) if count else 0
        except redis.RedisError:
            return 0
    
    def reset_counter(self, tenant_id: str, source_ip: str):
        """Reset counter for an IP (for testing/management)."""
        if self.redis_client is None:
            return
        
        try:
            key = self._get_redis_key(tenant_id, source_ip)
            self.redis_client.delete(key)
            logger.info(f"Reset brute force counter for {source_ip}")
        except redis.RedisError as e:
            logger.error(f"Failed to reset counter: {e}")


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================
# Used by analyzer_manager for shared Redis connection
_analyzer_instance: Optional[BruteForceAnalyzer] = None


def get_analyzer(redis_client: Optional[redis.Redis] = None) -> BruteForceAnalyzer:
    """Get or create singleton analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = BruteForceAnalyzer(redis_client)
    return _analyzer_instance
