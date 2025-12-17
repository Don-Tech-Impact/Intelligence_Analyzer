"""Redis consumer service for log processing."""

import json
import logging
import time
from typing import Dict, Any, Optional
import redis
from redis.exceptions import RedisError, ConnectionError

from src.core.config import config
from src.models.database import NormalizedLog
from src.core.database import db_manager
from src.services.log_ingestion import LogIngestionService

logger = logging.getLogger(__name__)


class RedisConsumer:
    """Consumes logs from Redis queue and stores them in database."""
    
    def __init__(self):
        """Initialize Redis consumer."""
        self.redis_client: Optional[redis.Redis] = None
        self.running = False
        self.log_queue = config.redis_log_queue
        self.ingestion_service = LogIngestionService()
        
    def connect(self):
        """Establish connection to Redis."""
        try:
            self.redis_client = redis.Redis(
                host=config.redis_host,
                port=config.redis_port,
                db=config.redis_db,
                password=config.redis_password,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
                health_check_interval=30
            )
            # Test connection
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {config.redis_host}:{config.redis_port}")
        except (RedisError, ConnectionError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def disconnect(self):
        """Close Redis connection."""
        if self.redis_client:
            self.redis_client.close()
            logger.info("Disconnected from Redis")
    
    def parse_log_message(self, message: str) -> Optional[Dict[str, Any]]:
        """Parse log message from JSON string.
        
        Args:
            message: JSON string containing log data
            
        Returns:
            Parsed log dictionary or None if parsing fails
        """
        try:
            log_data = json.loads(message)
            return log_data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse log message: {e}")
            logger.debug(f"Invalid message: {message}")
            return None
    
    def process_message(self, message: str) -> bool:
        """Process a single log message.
        
        Args:
            message: Raw message from Redis
            
        Returns:
            True if processed successfully, False otherwise
        """
        log_data = self.parse_log_message(message)
        if log_data is None:
            return False
        
        # Use ingestion service to process (normalize, store, analyze)
        return self.ingestion_service.process_log(log_data)
    
    def start(self):
        """Start consuming logs from Redis queue."""
        if not self.redis_client:
            self.connect()
        
        self.running = True
        logger.info(f"Starting Redis consumer on queue: {self.log_queue}")
        
        consecutive_errors = 0
        max_consecutive_errors = 10
        
        while self.running:
            try:
                # BLPOP blocks until a message is available or timeout
                result = self.redis_client.blpop(self.log_queue, timeout=1)
                
                if result:
                    queue_name, message = result
                    logger.debug(f"Received message from {queue_name}")
                    
                    if self.process_message(message):
                        consecutive_errors = 0
                    else:
                        consecutive_errors += 1
                
            except (RedisError, ConnectionError) as e:
                logger.error(f"Redis error: {e}")
                consecutive_errors += 1
                
                if consecutive_errors >= max_consecutive_errors:
                    logger.error(f"Too many consecutive errors ({consecutive_errors}). Stopping consumer.")
                    self.running = False
                    break
                
                # Try to reconnect
                logger.info("Attempting to reconnect to Redis...")
                time.sleep(5)
                try:
                    self.connect()
                    consecutive_errors = 0
                except Exception as reconnect_error:
                    logger.error(f"Reconnection failed: {reconnect_error}")
            
            except KeyboardInterrupt:
                logger.info("Received interrupt signal")
                self.running = False
                break
            
            except Exception as e:
                logger.error(f"Unexpected error in consumer: {e}", exc_info=True)
                consecutive_errors += 1
                time.sleep(1)
        
        logger.info("Redis consumer stopped")
    
    def stop(self):
        """Stop the consumer."""
        logger.info("Stopping Redis consumer...")
        self.running = False
    
    def get_queue_size(self) -> int:
        """Get current size of the log queue.
        
        Returns:
            Number of messages in queue
        """
        if not self.redis_client:
            return 0
        try:
            return self.redis_client.llen(self.log_queue)
        except RedisError as e:
            logger.error(f"Failed to get queue size: {e}")
            return 0
