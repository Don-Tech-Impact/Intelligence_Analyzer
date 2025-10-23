"""Main SIEM Analyzer application."""

import logging
import signal
import sys
import time
from threading import Thread

from src.core.logging_config import setup_logging, get_logger
from src.core.config import config
from src.core.database import db_manager
from src.services.redis_consumer import RedisConsumer
from src.services.scheduler import TaskScheduler
from src.analyzers.base import analyzer_manager
from src.analyzers.brute_force import BruteForceAnalyzer
from src.analyzers.port_scan import PortScanAnalyzer
from src.analyzers.threat_intel import ThreatIntelAnalyzer

logger = get_logger(__name__)


class SIEMAnalyzer:
    """Main SIEM Analyzer application."""
    
    def __init__(self):
        """Initialize SIEM Analyzer."""
        self.redis_consumer = None
        self.scheduler = None
        self.running = False
        self.consumer_thread = None
    
    def initialize(self):
        """Initialize all components."""
        logger.info("Initializing SIEM Analyzer")
        
        # Initialize database
        logger.info("Initializing database...")
        db_manager.initialize()
        
        # Register analyzers
        logger.info("Registering threat analyzers...")
        analyzer_manager.register(BruteForceAnalyzer())
        analyzer_manager.register(PortScanAnalyzer())
        analyzer_manager.register(ThreatIntelAnalyzer())
        
        # Initialize Redis consumer
        logger.info("Initializing Redis consumer...")
        self.redis_consumer = RedisConsumer()
        
        # Initialize scheduler
        logger.info("Initializing task scheduler...")
        self.scheduler = TaskScheduler()
        
        logger.info("SIEM Analyzer initialized successfully")
    
    def start(self):
        """Start the SIEM Analyzer."""
        logger.info("Starting SIEM Analyzer")
        self.running = True
        
        # Start scheduler
        self.scheduler.start()
        
        # Start Redis consumer in separate thread
        self.consumer_thread = Thread(
            target=self._run_consumer,
            name='RedisConsumer',
            daemon=True
        )
        self.consumer_thread.start()
        
        logger.info("SIEM Analyzer started successfully")
        logger.info(f"Redis queue: {config.redis_log_queue}")
        logger.info(f"Database: {config.database_type}")
        logger.info(f"Email alerts: {'enabled' if config.email_enabled else 'disabled'}")
        logger.info(f"Reports: {'enabled' if config.report_enabled else 'disabled'}")
    
    def _run_consumer(self):
        """Run Redis consumer (executed in separate thread)."""
        try:
            self.redis_consumer.start()
        except Exception as e:
            logger.error(f"Redis consumer error: {e}", exc_info=True)
    
    def stop(self):
        """Stop the SIEM Analyzer."""
        logger.info("Stopping SIEM Analyzer")
        self.running = False
        
        # Stop Redis consumer
        if self.redis_consumer:
            self.redis_consumer.stop()
        
        # Stop scheduler
        if self.scheduler:
            self.scheduler.stop()
        
        # Wait for consumer thread
        if self.consumer_thread and self.consumer_thread.is_alive():
            logger.info("Waiting for consumer thread to finish...")
            self.consumer_thread.join(timeout=5)
        
        # Close database
        db_manager.close()
        
        logger.info("SIEM Analyzer stopped")
    
    def run(self):
        """Run the SIEM Analyzer (blocking)."""
        self.initialize()
        self.start()
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            self.stop()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info(f"Received signal {signum}")
        self.running = False


def main():
    """Main entry point."""
    # Setup logging
    setup_logging()
    
    logger.info("="*60)
    logger.info("SIEM Analyzer Starting")
    logger.info("="*60)
    
    try:
        # Create and run application
        app = SIEMAnalyzer()
        app.run()
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    
    logger.info("SIEM Analyzer exited")


if __name__ == '__main__':
    main()
