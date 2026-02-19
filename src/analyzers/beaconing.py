"""Beaconing (C2 Communication) Analyzer - Redis Edition.

=============================================================================
DETECTION LOGIC
=============================================================================
Detects: Command & Control heartbeats, periodic malware callbacks

Pattern: Regular, periodic connections from internal host to external destination
         with low timing jitter (variance).

Redis State:
    Key: bc:{tenant_id}:{source_ip}:{destination_ip}
    Type: SORTED SET (timestamps as scores)
    TTL: 14400 seconds (4 hours)
    
Performance:
    - O(log N) per log (ZADD + ZREMRANGEBYSCORE)
    - N is bounded by 4-hour window (~max 1000s of entries)
    - Still much faster than unbounded DB queries
    
Accuracy:
    - Exact timestamps, exact jitter calculation
    - Uses same algorithm as original DB-based version
    - Sorted set maintains order for interval calculation
=============================================================================
"""

import logging
import os
import redis
import numpy as np
from typing import Optional, List, Tuple
from datetime import datetime

from src.core.config import config
from src.models.database import Alert

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================
# Minimum connections to analyze (need enough data points for jitter)
BEACON_MIN_OCCURRENCES = int(os.getenv('BEACON_MIN_OCCURRENCES', 5))
# Maximum jitter ratio (stddev/mean) - lower = more regular = more suspicious
BEACON_JITTER_THRESHOLD = float(os.getenv('BEACON_JITTER_THRESHOLD', 0.2))
# Window for tracking connections (4 hours)
BEACON_WINDOW_SECONDS = int(os.getenv('BEACON_WINDOW_SECONDS', 14400))


class BeaconingAnalyzer:
    """
    Detects C2 beaconing using Redis sorted sets.
    
    Replaces: SELECT timestamp FROM logs 
              WHERE source_ip=? AND destination_ip=? AND timestamp > ?
              ORDER BY timestamp
    With: Redis ZADD + ZRANGE (bounded O(log N) vs unbounded O(n))
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize analyzer with Redis client.
        
        Args:
            redis_client: Shared Redis connection. If None, creates new one.
        """
        # Required attributes for AnalyzerManager
        self.name = "BeaconingAnalyzer"
        self.enabled = True
        
        self.redis_client = redis_client
        self.min_occurrences = BEACON_MIN_OCCURRENCES
        self.jitter_threshold = BEACON_JITTER_THRESHOLD
        self.window_seconds = BEACON_WINDOW_SECONDS
        
        if self.redis_client is None:
            self._connect_redis()
        
        logger.info(
            f"BeaconingAnalyzer initialized: "
            f"min_occurrences={self.min_occurrences}, "
            f"jitter_threshold={self.jitter_threshold}, "
            f"window={self.window_seconds}s"
        )
    
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
        Generate Redis key for beaconing tracking.
        
        Pattern: bc:{tenant_id}:{source_ip}:{destination_ip}
        Example: bc:acme_corp:192.168.1.100:evil.c2server.com
        """
        return f"bc:{tenant_id}:{source_ip}:{dest_ip}"
    
    def _get_timestamp_epoch(self, log) -> float:
        """Extract timestamp as epoch seconds from log."""
        timestamp = getattr(log, 'timestamp', None)
        
        if timestamp is None:
            return datetime.utcnow().timestamp()
        
        if isinstance(timestamp, datetime):
            try:
                # Windows can't handle dates before 1970
                return timestamp.timestamp()
            except (OSError, ValueError):
                return datetime.utcnow().timestamp()
        
        if isinstance(timestamp, (int, float)):
            return float(timestamp)
        
        # Try parsing string
        try:
            return datetime.fromisoformat(str(timestamp).replace('Z', '+00:00')).timestamp()
        except:
            return datetime.utcnow().timestamp()
    
    def _calculate_jitter(self, timestamps: List[float]) -> Tuple[float, float, float]:
        """
        Calculate timing jitter for a series of connection timestamps.
        
        Returns:
            Tuple of (jitter_ratio, mean_interval, std_interval)
            jitter_ratio = std / mean (lower = more regular)
        """
        if len(timestamps) < 2:
            return (float('inf'), 0, 0)
        
        # Calculate intervals between consecutive timestamps
        intervals = np.diff(sorted(timestamps))
        
        if len(intervals) == 0:
            return (float('inf'), 0, 0)
        
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        # Avoid division by zero
        if mean_interval == 0:
            return (float('inf'), 0, 0)
        
        jitter_ratio = std_interval / mean_interval
        
        return (jitter_ratio, mean_interval, std_interval)
    
    def analyze(self, log) -> Optional[Alert]:
        """
        Analyze log for C2 beaconing patterns.
        
        Algorithm:
            1. Add timestamp to Redis sorted set for this src/dst pair
            2. Remove old timestamps outside window (ZREMRANGEBYSCORE)
            3. Get all timestamps in window (ZRANGE)
            4. If count < min_occurrences → return None (not enough data)
            5. Calculate jitter (timing variance)
            6. If jitter <= threshold → Create alert (regular = suspicious)
        
        Args:
            log: NormalizedLog or log-like object with attributes
            
        Returns:
            Alert if beaconing detected, None otherwise
        """
        # Get required fields
        source_ip = getattr(log, 'source_ip', None)
        dest_ip = getattr(log, 'destination_ip', None)
        tenant_id = getattr(log, 'tenant_id', 'default')
        
        # Skip if missing required fields
        if not source_ip or not dest_ip:
            return None
        
        # Skip same-IP traffic (not beaconing)
        if source_ip == dest_ip:
            return None
        
        # Skip if Redis unavailable
        if self.redis_client is None:
            logger.warning("Redis unavailable, skipping beaconing analysis")
            return None
        
        try:
            key = self._get_redis_key(tenant_id, source_ip, dest_ip)
            now = self._get_timestamp_epoch(log)
            cutoff = now - self.window_seconds
            
            # =========================================================
            # REDIS STATE UPDATE
            # =========================================================
            # Use pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            
            # Add current timestamp (score = timestamp for ordering)
            # Member includes microseconds for uniqueness
            member = f"{now:.6f}"
            pipe.zadd(key, {member: now})
            
            # Remove old timestamps outside window
            pipe.zremrangebyscore(key, 0, cutoff)
            
            # Refresh TTL
            pipe.expire(key, self.window_seconds)
            
            # Get all timestamps in current window
            pipe.zrange(key, 0, -1, withscores=True)
            
            results = pipe.execute()
            
            # Results: [zadd_count, removed_count, expire_result, timestamps]
            timestamp_pairs = results[3]  # List of (member, score) tuples
            timestamps = [score for member, score in timestamp_pairs]
            
            # =========================================================
            # ANALYSIS
            # =========================================================
            if len(timestamps) < self.min_occurrences:
                logger.debug(f"Beaconing check {source_ip}→{dest_ip}: {len(timestamps)} connections (need {self.min_occurrences})")
                return None
            
            jitter_ratio, mean_interval, std_interval = self._calculate_jitter(timestamps)
            
            logger.debug(
                f"Beaconing analysis {source_ip}→{dest_ip}: "
                f"connections={len(timestamps)}, "
                f"jitter={jitter_ratio:.3f}, "
                f"mean_interval={mean_interval:.1f}s"
            )
            
            # =========================================================
            # ALERT GENERATION
            # =========================================================
            if jitter_ratio <= self.jitter_threshold:
                alert = Alert(
                    tenant_id=tenant_id,
                    alert_type='beaconing',
                    severity='critical',  # C2 = critical
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    description=(
                        f"Potential C2 beaconing detected: {source_ip} → {dest_ip} "
                        f"with {len(timestamps)} regular connections "
                        f"(interval: {mean_interval:.1f}s ± {std_interval:.1f}s, jitter: {jitter_ratio:.3f})"
                    ),
                    details={
                        'connection_count': len(timestamps),
                        'mean_interval_seconds': round(mean_interval, 2),
                        'std_interval_seconds': round(std_interval, 2),
                        'jitter_ratio': round(jitter_ratio, 4),
                        'jitter_threshold': self.jitter_threshold,
                        'window_hours': self.window_seconds / 3600,
                        'detection_method': 'redis_sorted_set',
                        'first_seen': datetime.fromtimestamp(min(timestamps)).isoformat(),
                        'last_seen': datetime.fromtimestamp(max(timestamps)).isoformat()
                    },
                    status='open'
                )
                
                logger.warning(
                    f"ALERT: Beaconing detected {source_ip}→{dest_ip} "
                    f"(jitter={jitter_ratio:.3f} <= {self.jitter_threshold})"
                )
                
                return alert
            
            return None
            
        except redis.RedisError as e:
            logger.error(f"Redis error in beaconing analysis: {e}")
            return None
        except Exception as e:
            logger.error(f"Error in beaconing analysis: {e}", exc_info=True)
            return None
    
    def get_connection_history(self, tenant_id: str, source_ip: str, dest_ip: str) -> List[datetime]:
        """Get connection timestamps for debugging/API."""
        if self.redis_client is None:
            return []
        
        try:
            key = self._get_redis_key(tenant_id, source_ip, dest_ip)
            timestamps = self.redis_client.zrange(key, 0, -1, withscores=True)
            return [datetime.fromtimestamp(score) for _, score in timestamps]
        except redis.RedisError:
            return []
    
    def reset_tracking(self, tenant_id: str, source_ip: str, dest_ip: str):
        """Reset tracking for a source/dest pair."""
        if self.redis_client is None:
            return
        
        try:
            key = self._get_redis_key(tenant_id, source_ip, dest_ip)
            self.redis_client.delete(key)
            logger.info(f"Reset beaconing tracking for {source_ip}→{dest_ip}")
        except redis.RedisError as e:
            logger.error(f"Failed to reset tracking: {e}")


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================
_analyzer_instance: Optional[BeaconingAnalyzer] = None


def get_analyzer(redis_client: Optional[redis.Redis] = None) -> BeaconingAnalyzer:
    """Get or create singleton analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = BeaconingAnalyzer(redis_client)
    return _analyzer_instance
