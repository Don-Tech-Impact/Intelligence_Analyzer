
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

# --- Basic Logging Setup ---
# This sets the logging level and format for terminal output.
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

        # --- Start the Consumer ---
        redis_consumer = RedisConsumer()
        redis_consumer.connect()
        # redis_consumer.start() # This will block and run forever until you press Ctrl+C
        
        # --- Check for data in the queue ---
        queue_name = settings.redis.log_queue
        queue_size = redis_consumer.get_queue_size()
        logger.info(f"Current size of Redis queue '{queue_name}': {queue_size}")
        logger.info(f"Checking Redis queue '{queue_name}'...")
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


if __name__ == "__main__":
    run_consumer_with_analyzers()