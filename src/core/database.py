"""Database management and session handling."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from typing import Generator
import logging

from src.models.database import Base
from src.core.config import config

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions."""
    
    def __init__(self):
        """Initialize database manager."""
        self.engine = None
        self.session_factory = None
        self.Session = None
        
    def initialize(self):
        """Initialize database engine and create tables."""
        database_url = config.database_url
        logger.info(f"Initializing database: {database_url.split('@')[-1] if '@' in database_url else database_url}")
        
        # Create engine with appropriate settings
        if config.database_type == 'sqlite':
            # SQLite specific settings
            self.engine = create_engine(
                database_url,
                connect_args={'check_same_thread': False}, ## Needed for SQLite to allow multi-threaded access
                poolclass=StaticPool, # Use StaticPool for SQLite
                echo=False # Disable SQL echoing
            )
        else:
            # PostgreSQL settings
            self.engine = create_engine(
                database_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                echo=False
            )
        
        # Create session factory
        self.session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(self.session_factory) # Thread-safe sessions and safe from race conditions
        
        # Create all tables
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created successfully")
    
    ## this is for controlling the session outside the context manager and aswell the session scope
    def get_session(self):
        """Get a new database session.
        
        Returns:
            SQLAlchemy session
        """
        if self.Session is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.Session()
    
    @contextmanager # it imports context manager from contextlib and impplement the entire database transaction
    def session_scope(self) -> Generator:
        """Provide a transactional scope for database operations.
        
        Yields:
            SQLAlchemy session
        """
        session = self.get_session() # get me a fresh session
        try:
            yield session # yield it to the caller 
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def close(self):
        """Close database connections."""
        if self.Session:
            self.Session.remove()
        if self.engine:
            self.engine.dispose()
        logger.info("Database connections closed")


# Global database manager instance
db_manager = DatabaseManager()
