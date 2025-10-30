# """Redis consumer service for log processing."""

# import json
# import logging
# import time
# from typing import Dict, Any, Optional
# import redis
# from redis.exceptions import RedisError, ConnectionError

# from src.core.config import config
# from src.models.database import Log
# from src.core.database import db_manager

# logger = logging.getLogger(__name__)


# class RedisConsumer:
#     """Consumes logs from Redis queue and stores them in database."""
    
#     def __init__(self):
#         """Initialize Redis consumer."""
#         self.redis_client: Optional[redis.Redis] = None
#         self.running = False
#         self.log_queue = config.redis_log_queue
        
#     def connect(self):
#         """Establish connection to Redis."""
#         try:
#             self.redis_client = redis.Redis(
#                 host=config.redis_host,
#                 port=config.redis_port,
#                 db=config.redis_db,
#                 password=config.redis_password,
#                 decode_responses=True,
#                 socket_connect_timeout=5,
#                 socket_keepalive=True,
#                 health_check_interval=30
#             )
#             # Test connection
#             self.redis_client.ping()
#             logger.info(f"Connected to Redis at {config.redis_host}:{config.redis_port}")
#         except (RedisError, ConnectionError) as e:
#             logger.error(f"Failed to connect to Redis: {e}")
#             raise
    
#     def disconnect(self):
#         """Close Redis connection."""
#         if self.redis_client:
#             self.redis_client.close()
#             logger.info("Disconnected from Redis")
    
#     def parse_log_message(self, message: str) -> Optional[Dict[str, Any]]:
#         """Parse log message from JSON string.
        
#         Args:
#             message: JSON string containing log data
            
#         Returns:
#             Parsed log dictionary or None if parsing fails
#         """
#         try:
#             log_data = json.loads(message)
#             return log_data
#         except json.JSONDecodeError as e:
#             logger.error(f"Failed to parse log message: {e}")
#             logger.debug(f"Invalid message: {message}")
#             return None
    
#     def store_log(self, log_data: Dict[str, Any]) -> Optional[Log]:
#         """Store log entry in database.
        
#         Args:
#             log_data: Parsed log data dictionary
            
#         Returns:
#             Created Log object or None if storage fails
#         """
#         try:
#             with db_manager.session_scope() as session:
#                 log_entry = Log(
#                     tenant_id=log_data.get('tenant_id', config.default_tenant),
#                     timestamp=log_data.get('timestamp'),
#                     source_ip=log_data.get('source_ip'),
#                     destination_ip=log_data.get('destination_ip'),
#                     source_port=log_data.get('source_port'),
#                     destination_port=log_data.get('destination_port'),
#                     protocol=log_data.get('protocol'),
#                     action=log_data.get('action'),
#                     log_type=log_data.get('log_type', 'generic'),
#                     message=log_data.get('message', ''),
#                     raw_data=log_data
#                 )
#                 session.add(log_entry)
#                 session.commit()
#                 logger.debug(f"Stored log entry: {log_entry.id}")
#                 return log_entry
#         except Exception as e:
#             logger.error(f"Failed to store log entry: {e}")
#             return None
    
#     def process_message(self, message: str) -> bool:
#         """Process a single log message.
        
#         Args:
#             message: Raw message from Redis
            
#         Returns:
#             True if processed successfully, False otherwise
#         """
#         log_data = self.parse_log_message(message)
#         if log_data is None:
#             return False
        
#         log_entry = self.store_log(log_data)
#         return log_entry is not None
    
#     def start(self):
#         """Start consuming logs from Redis queue."""
#         if not self.redis_client:
#             self.connect()
        
#         self.running = True
#         logger.info(f"Starting Redis consumer on queue: {self.log_queue}")
        
#         consecutive_errors = 0
#         max_consecutive_errors = 10
        
#         while self.running:
#             try:
#                 # BLPOP blocks until a message is available or timeout
#                 result = self.redis_client.blpop(self.log_queue, timeout=1)
                
#                 if result:
#                     queue_name, message = result
#                     logger.debug(f"Received message from {queue_name}")
                    
#                     if self.process_message(message):
#                         consecutive_errors = 0
#                     else:
#                         consecutive_errors += 1
                
#             except (RedisError, ConnectionError) as e:
#                 logger.error(f"Redis error: {e}")
#                 consecutive_errors += 1
                
#                 if consecutive_errors >= max_consecutive_errors:
#                     logger.error(f"Too many consecutive errors ({consecutive_errors}). Stopping consumer.")
#                     self.running = False
#                     break
                
#                 # Try to reconnect
#                 logger.info("Attempting to reconnect to Redis...")
#                 time.sleep(5)
#                 try:
#                     self.connect()
#                     consecutive_errors = 0
#                 except Exception as reconnect_error:
#                     logger.error(f"Reconnection failed: {reconnect_error}")
            
#             except KeyboardInterrupt:
#                 logger.info("Received interrupt signal")
#                 self.running = False
#                 break
            
#             except Exception as e:
#                 logger.error(f"Unexpected error in consumer: {e}", exc_info=True)
#                 consecutive_errors += 1
#                 time.sleep(1)
        
#         logger.info("Redis consumer stopped")
    
#     def stop(self):
#         """Stop the consumer."""
#         logger.info("Stopping Redis consumer...")
#         self.running = False
    
#     def get_queue_size(self) -> int:
#         """Get current size of the log queue.
        
#         Returns:
#             Number of messages in queue
#         """
#         if not self.redis_client:
#             return 0
#         try:
#             return self.redis_client.llen(self.log_queue)
#         except RedisError as e:
#             logger.error(f"Failed to get queue size: {e}")
#             return 0


"""Redis consumer service for log processing."""

import json
import logging
import time
from datetime import datetime
from typing import Optional

import redis
from redis.exceptions import RedisError, ConnectionError

from src.core.config import config
from src.models.database import Log
from src.analyzers.base import analyzer_manager  # <-- Import the analyzer manager

logger = logging.getLogger(__name__)


class RedisConsumer:
    """Consumes logs from Redis, passes them to analyzers."""
    
    def __init__(self):
        """Initialize Redis consumer."""
        self.redis_client: Optional[redis.Redis] = None
        self.running = False
        self.log_queue = config.redis_log_queue
        self.analyzer_manager = analyzer_manager # <-- Get the global analyzer manager instance

    def connect(self):
        """Establish connection to Redis."""
        try:
            self.redis_client = redis.Redis(
                host=config.redis_host,
                port=config.redis_port,
                db=config.redis_db,
                decode_responses=True,
                socket_connect_timeout=5
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {config.redis_host}:{config.redis_port}")
        except (RedisError, ConnectionError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _parse_log(self, log_data: str) -> Optional[Log]:
        """Parse a JSON log string into a Log object."""
        try:
            log_dict = json.loads(log_data)
            
            # --- CRITICAL: Parse the timestamp string into a datetime object ---
            timestamp_str = log_dict.get('timestamp')
            if not timestamp_str:
                logger.warning("Log message missing timestamp.")
                return None
            
            # Python's fromisoformat before 3.11 doesn't like 'Z', so we replace it
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

            return Log(
                timestamp=timestamp,
                source_ip=log_dict.get('source_ip'),
                log_type=log_dict.get('log_type'),
                action=log_dict.get('action'),
                message=log_dict.get('message'),
                raw_data=log_dict, # Store the original dict
                tenant_id='default' # Or get from log if available
            )
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON log: {log_data}")
            return None
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to parse timestamp or create Log object: {e}")
            return None

    def start(self):
        """Start consuming logs from Redis queue."""
        if not self.redis_client:
            self.connect()
        
        self.running = True
        logger.info(f"Starting Redis consumer on queue: {self.log_queue}")
        
        while self.running:
            try:
                # Block for 1 second waiting for a log
                result = self.redis_client.blpop(self.log_queue, timeout=1)
                
                if not result:
                    continue # Timeout, loop again
                
                _queue_name, message = result
                
                # 1. Parse the log
                log_entry = self._parse_log(message)
                
                if log_entry:
                    # 2. Pass the parsed log to the analyzers
                    logger.debug(f"Processing log from {log_entry.source_ip} at {log_entry.timestamp}")
                    self.analyzer_manager.process_log(log_entry)

            except (RedisError, ConnectionError) as e:
                logger.error(f"Redis error: {e}. Attempting to reconnect...")
                time.sleep(5)
                self.connect()
            except Exception as e:
                logger.error(f"Unexpected error in consumer loop: {e}", exc_info=True)
                time.sleep(1)
        
        logger.info("Redis consumer stopped")
    
    def stop(self):
        """Stop the consumer."""
        logger.info("Stopping Redis consumer...")
        self.running = False
