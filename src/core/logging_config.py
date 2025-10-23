"""Logging configuration for SIEM Analyzer."""

import logging
import logging.handlers
import os
from pathlib import Path
from pythonjsonlogger import jsonlogger

from src.core.config import config


def setup_logging():
    """Configure logging for the application."""
    # Create logs directory if it doesn't exist
    log_file = config.log_file
    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Get log level
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with standard formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler with JSON formatting (for log analysis)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count
    )
    file_handler.setLevel(log_level)
    json_formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        timestamp=True
    )
    file_handler.setFormatter(json_formatter)
    root_logger.addHandler(file_handler)
    
    # Log startup message
    root_logger.info("Logging system initialized")
    root_logger.info(f"Log level: {config.log_level}")
    root_logger.info(f"Log file: {log_file}")
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
