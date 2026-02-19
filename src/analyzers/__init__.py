"""Threat analyzers package.

=============================================================================
ARCHITECTURE
=============================================================================
All analyzers use Redis for state management:
- BruteForceAnalyzer: INCR counters (bf:{tenant}:{ip})
- PortScanAnalyzer: SADD sets (ps:{tenant}:{src}:{dst})
- BeaconingAnalyzer: ZADD sorted sets (bc:{tenant}:{src}:{dst})
- PayloadAnalysisAnalyzer: Pure regex (no state)

Analyzers share a single Redis connection for efficiency.
They are automatically registered with analyzer_manager on import.
=============================================================================
"""

import logging
import redis
from src.core.config import config

logger = logging.getLogger(__name__)

# =============================================================================
# SHARED REDIS CONNECTION
# =============================================================================
# All Redis-based analyzers share this connection
_shared_redis: redis.Redis = None


def get_shared_redis() -> redis.Redis:
    """Get or create shared Redis connection for analyzers."""
    global _shared_redis
    if _shared_redis is None:
        try:
            _shared_redis = redis.from_url(
                config.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
                health_check_interval=30
            )
            _shared_redis.ping()
            logger.info("Analyzer Redis connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis for analyzers: {e}")
            _shared_redis = None
    return _shared_redis


# =============================================================================
# IMPORT AND REGISTER ANALYZERS
# =============================================================================
from src.analyzers.base import analyzer_manager, BaseAnalyzer, AnalyzerManager
from src.analyzers.brute_force import BruteForceAnalyzer
from src.analyzers.port_scan import PortScanAnalyzer
from src.analyzers.beaconing import BeaconingAnalyzer
from src.analyzers.payload_analysis import PayloadAnalysisAnalyzer, PayloadAnalyzer

# Get shared Redis for all analyzers
_redis = get_shared_redis()

# Create analyzer instances with shared Redis
_analyzers = [
    BruteForceAnalyzer(redis_client=_redis),
    PortScanAnalyzer(redis_client=_redis),
    BeaconingAnalyzer(redis_client=_redis),
    PayloadAnalysisAnalyzer(),  # No Redis needed (pure regex)
]

# Register all analyzers
for analyzer in _analyzers:
    analyzer_manager.register(analyzer)

logger.info(f"Registered {len(_analyzers)} analyzers")

__all__ = [
    'analyzer_manager',
    'BaseAnalyzer',
    'AnalyzerManager',
    'BruteForceAnalyzer',
    'PortScanAnalyzer',
    'BeaconingAnalyzer',
    'PayloadAnalysisAnalyzer',
    'PayloadAnalyzer',
    'get_shared_redis',
]
