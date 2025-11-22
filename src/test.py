
# from config.config import settings
# import logging
# # import signal
# # import sys
# # import time
# # from threading import Thread

# from src.core.logging_config import setup_logging, get_logger
# from src.core.config import config
# # from src.core.database import db_manager
# from src.services.redis_consumer import RedisConsumer
# # from src.services.scheduler import TaskScheduler
# # from src.analyzers.base import analyzer_manager
# # from src.analyzers.brute_force import BruteForceAnalyzer
# # from src.analyzers.port_scan import PortScanAnalyzer
# # from src.analyzers.threat_intel import ThreatIntelAnalyzer

# logging.basicConfig(level=settings.log_level)
# logger = get_logger(__name__)




# def _run_consumer():
#         """Run Redis consumer (executed in separate thread)."""
#         try:
#             redis_consumer = RedisConsumer()
#             redis_consumer.start()
#         except Exception as e:
#             logger.error(f"Redis consumer error: {e}", exc_info=True)
            
            
# if __name__ == "__main__":
#     _run_consumer()


"""
Simple test runner to start the Redis consumer and see its output.
"""
import logging
from config.config import settings
from src.services.redis_consumer import RedisConsumer
from src.analyzers.base import analyzer_manager
from src.analyzers.brute_force import BruteForceAnalyzer
from src.analyzers.port_scan import PortScanAnalyzer

from src.core.database import db_manager

# --- Basic Logging Setup ---
# This sets the logging level and format for terminal output.
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def dump_queue(redis_consumer: RedisConsumer) -> None:
        queue = settings.redis.log_queue
        raw_items = redis_consumer.redis_client.lrange(queue, 0, -1)  # type: ignore[attr-defined]
        if not raw_items:
            logger.warning(f"No messages in '{queue}'.")
            return

        logger.info(f"Dumping {len(raw_items)} messages from '{queue}':")
        for idx, item in enumerate(raw_items, 1):
            logger.info("[%d] %s", idx, item)

    # def run_consumer_with_analyzers():
    #     # ...existing code...
    #         redis_consumer = RedisConsumer()
    #         redis_consumer.connect()

    #         dump_queue(redis_consumer)        # <-- print everything first
    #         redis_consumer.start()  

def run_consumer_with_analyzers():
    """
    Initializes and runs the Redis consumer with registered analyzers.
    """
    logger.info("========================================")
    logger.info("SIEM Analyzer Test Runner Starting")
    logger.info(f"Log Level: {settings.log_level}")
    logger.info("========================================")

    try:
        # --- Register Analyzers ---
        # In a real app, this happens in main.py, but we do it here for testing.
        logger.info("Registering threat analyzers...")
        analyzer_manager.register(BruteForceAnalyzer())
        analyzer_manager.register(PortScanAnalyzer())
        logger.info("Analyzers registered.")

        db_manager.initialize()
        # --- Start the Consumer ---
        redis_consumer = RedisConsumer()
        redis_consumer.connect()
        dump_queue(redis_consumer)
        # redis_consumer.start() # This will block and run forever until you press Ctrl+C
        
        # --- Check for data in the queue ---
        queue_name = settings.redis.log_queue
        queue_size = redis_consumer.get_queue_size()
        # get_log_message = redis_consumer.get_log_message()
        #dump_queue = redis_consumer.dump_queue(5)
        # dump_queue = redis_consumer.dump_queue(5)
        
        
        logger.info(f"Current size of Redis queue '{queue_name}': {queue_size}")
        logger.info(f"Checking Redis queue '{queue_name}'...")
        
        # logger.info(f"Sample log message from queue: {get_log_message}")
        
        if queue_size > 0:
            logger.info(f"SUCCESS: Found {queue_size} logs waiting in the queue.")
        else:
            logger.warning(f"NOTICE: The queue '{queue_name}' is currently empty.")
            logger.warning("The consumer will now wait for new logs to arrive.")
        
        # --- Start the main processing loop ---
        redis_consumer.start() # This will block and run forever until you press Ctrl+C
    except Exception as e:
        logger.error(f"A fatal error occurred: {e}", exc_info=True)
    finally:
        logger.info("SIEM Analyzer Test Runner Shutting Down.")


def test_bruteforce_replay():
    from src.core.database import db_manager
    from scripts.replay_bruteforce import replay_all
    db_manager.initialize()
    replay_all(auth_only=True)
    # optionally assert alert count increased, etc.
    
    
    # Simulate log entries and test the analyzer logic here
    


if __name__ == "__main__":
    # run_consumer_with_analyzers()
    run_consumer_with_analyzers()