"""Database management and session handling."""

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from sqlalchemy.pool import StaticPool, NullPool
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
            # In-memory SQLite (tests): must use StaticPool to keep the
            # same connection alive, otherwise tables vanish.
            # File-based SQLite (production): use NullPool so each session
            # opens a fresh connection that sees writes from other processes
            # (e.g., the consumer writing while the API reads).
            is_memory = ':memory:' in database_url or database_url == 'sqlite://'
            self.engine = create_engine(
                database_url,
                connect_args={'check_same_thread': False},
                poolclass=StaticPool if is_memory else NullPool,
                echo=False
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
        self.Session = scoped_session(self.session_factory)
        
        # Create all tables
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created successfully")
    
    def get_session(self):
        """Get a new database session.
        
        Returns:
            SQLAlchemy session
        """
        if self.Session is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.Session()
    
    @contextmanager
    def session_scope(self) -> Generator:
        """Provide a transactional scope for database operations.
        
        Yields:
            SQLAlchemy session
        """
        session = self.get_session()
        try:
            yield session
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

# ================================================
# MULTI-TENANCY SECURITY ENFORCEMENT
# ================================================
@event.listens_for(Session, 'after_begin')
def set_tenant_context(session, transaction, connection):
    if hasattr(session, 'info') and 'tenant_id' in session.info:
        tenant_id = session.info['tenant_id']
        session.execute(text(f"SET app.current_tenant = '{tenant_id}'"))
