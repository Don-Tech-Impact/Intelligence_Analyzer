import redis
import logging
from src.core.config import config

logger = logging.getLogger(__name__)

# Initialize a thread-safe Redis client using the configured URL
try:
    redis_client = redis.from_url(
        config.redis_url,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_keepalive=True,
        health_check_interval=30
    )
    # Ping once to verify connection on startup
    # Note: We don't block the whole app if Redis is down, but we log the error
    try:
        redis_client.ping()
        logger.info("Redis client initialized and connected successfully.")
    except Exception as e:
        logger.warning(f"Redis client initialized but could not connect: {e}")
except Exception as e:
    logger.error(f"Failed to initialize Redis client: {e}")
    # Provide a dummy client or let it fail on first use
    redis_client = None
