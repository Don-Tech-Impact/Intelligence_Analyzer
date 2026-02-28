"""Database models for SIEM Analyzer.

=============================================================================
ARCHITECTURE NOTES
=============================================================================
- PostgreSQL with time-based partitioning (monthly) for logs table
- Row-Level Security (RLS) enforced at database level
- Models here define SQLAlchemy ORM mappings
- Actual table creation is in scripts/init_db.sql (includes partitioning)
=============================================================================
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, BigInteger, String, DateTime, Text, Boolean, Float, 
    ForeignKey, Index, JSON, event
)

# SQLite only auto-increments "INTEGER PRIMARY KEY" (not BIGINT).
# This type uses BigInteger on PostgreSQL but Integer on SQLite.
PortableBigInt = BigInteger().with_variant(Integer(), "sqlite")
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import declarative_base, relationship, Session

Base = declarative_base()


# =============================================================================
# Helper: Set tenant context for RLS
# =============================================================================
def set_tenant_context(session: Session, tenant_id: str):
    """
    Set the current tenant for Row-Level Security.
    Must be called before any query that should be tenant-isolated.
    
    Usage:
        with db_manager.session_scope() as session:
            set_tenant_context(session, 'tenant_123')
            logs = session.query(NormalizedLog).all()  # Only tenant_123 logs
    """
    session.execute(f"SET app.current_tenant = '{tenant_id}'")


class NormalizedLog(Base):
    """
    Normalized log entry model.
    
    Table is partitioned by timestamp (monthly) in PostgreSQL.
    Primary key includes timestamp to support partitioning.
    """
    __tablename__ = 'logs'
    
    # PostgreSQL partitioning (composite PK) is handled by init_db.sql.
    # SQLAlchemy model uses single PK for cross-DB compatibility.
    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Tenant isolation
    tenant_id = Column(String(64), nullable=False, default='default', index=True)
    
    # Device identification
    company_id = Column(String(100), index=True, nullable=True)
    device_id = Column(String(100), index=True, nullable=True)
    
    # Network fields (PostgreSQL INET type for efficient IP operations)
    source_ip = Column(String(45), index=True)  # Using String for SQLite compatibility
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(16))
    
    # Log metadata
    action = Column(String(32))
    log_type = Column(String(64), index=True)
    vendor = Column(String(64), index=True)
    device_hostname = Column(String(128), index=True)
    severity = Column(String(16), default='low', index=True)  # low, medium, high, critical
    
    # Content
    message = Column(Text)
    raw_data = Column(JSON)  # Full original log for forensics
    business_context = Column(JSON)  # Enrichment data (GeoIP, threat score, etc.)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # =========================================================================
    # INDEX STRATEGY
    # =========================================================================
    # - Primary queries: Filter by tenant + time range
    # - IP lookups: Threat correlation
    # - Severity: Dashboard widgets
    # =========================================================================
    __table_args__ = (
        # Composite index for tenant + time queries (most common)
        Index('idx_logs_tenant_timestamp', 'tenant_id', 'timestamp'),
        # IP-based correlation
        Index('idx_logs_source_ip_timestamp', 'source_ip', 'timestamp'),
        Index('idx_logs_dest_ip_timestamp', 'destination_ip', 'timestamp'),
        # Log type filtering
        Index('idx_logs_type_tenant', 'log_type', 'tenant_id'),
        # Severity-based queries
        Index('idx_logs_tenant_severity', 'tenant_id', 'severity', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<NormalizedLog(id={self.id}, source_ip={self.source_ip}, timestamp={self.timestamp})>"
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'tenant_id': self.tenant_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'action': self.action,
            'log_type': self.log_type,
            'vendor': self.vendor,
            'severity': self.severity,
            'message': self.message,
            'business_context': self.business_context
        }


class DeadLetter(Base):
    """
    Failed logs that couldn't be processed.
    
    Used for:
    - Audit trail of failed ingestion
    - Debugging parsing/validation issues
    - Potential re-processing after fixes
    
    No partitioning: Low volume, infrequently queried.
    """
    __tablename__ = 'dead_letters'
    
    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), index=True)
    received_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    source_queue = Column(String(64))  # Which queue it came from
    error_type = Column(String(64))  # validation_error, parse_error, db_error, etc.
    error_message = Column(Text)
    raw_payload = Column(JSON, nullable=False)  # Original message for debugging
    retry_count = Column(Integer, default=0)
    last_retry_at = Column(DateTime(timezone=True))
    
    __table_args__ = (
        Index('idx_dead_letters_tenant_received', 'tenant_id', 'received_at'),
        Index('idx_dead_letters_error_type', 'error_type', 'received_at'),
    )
    
    def __repr__(self):
        return f"<DeadLetter(id={self.id}, error_type={self.error_type})>"


class Alert(Base):
    """Security alert model."""
    __tablename__ = 'alerts'
    
    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=False, default='default', index=True)
    company_id = Column(String(100), index=True, nullable=True)
    device_id = Column(String(100), index=True, nullable=True)
    
    alert_type = Column(String(64), nullable=False, index=True)  # brute_force, port_scan, beaconing, threat_intel
    severity = Column(String(16), nullable=False, default='medium', index=True)
    
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    
    description = Column(Text)
    details = Column(JSON)  # Additional structured data
    
    status = Column(String(32), default='open', index=True)  # open, acknowledged, investigating, resolved
    notified = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    __table_args__ = (
        Index('idx_alerts_tenant_status', 'tenant_id', 'status', 'created_at'),
        Index('idx_alerts_tenant_severity', 'tenant_id', 'severity', 'created_at'),
        Index('idx_alerts_source_ip', 'source_ip', 'created_at'),
    )
    
    def __repr__(self):
        return f"<Alert(id={self.id}, type={self.alert_type}, severity={self.severity})>"
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'tenant_id': self.tenant_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'description': self.description,
            'details': self.details,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ThreatIntelligence(Base):
    """Threat intelligence indicator model."""
    __tablename__ = 'threat_intelligence'
    
    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    indicator_type = Column(String(32), nullable=False, index=True)  # ip, domain, hash, url
    indicator_value = Column(String(256), nullable=False, unique=True, index=True)
    threat_type = Column(String(64))  # malware, botnet, phishing, c2, scanner
    confidence = Column(Float)  # 0.0 to 1.0
    source = Column(String(128))  # Feed name
    description = Column(Text)
    first_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_threat_intel_active', 'indicator_type', 'indicator_value', 'is_active'),
    )
    
    def __repr__(self):
        return f"<ThreatIntelligence(type={self.indicator_type}, value={self.indicator_value})>"


class Report(Base):
    """Generated report model."""
    __tablename__ = 'reports'
    
    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), default='default', index=True)
    report_type = Column(String(32), nullable=False)  # daily, weekly, monthly, custom
    start_date = Column(DateTime(timezone=True), nullable=False)
    end_date = Column(DateTime(timezone=True), nullable=False)
    total_logs = Column(Integer)
    total_alerts = Column(Integer)
    alerts_by_severity = Column(JSON)
    top_source_ips = Column(JSON)
    top_alert_types = Column(JSON)
    file_path = Column(String(256))
    summary = Column(JSON)
    format = Column(String(20))  # html, csv, pdf
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Report(id={self.id}, type={self.report_type})>"


class Tenant(Base):
    """Multi-tenant configuration model."""
    __tablename__ = 'tenants'
    
    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text)
    settings = Column(JSON, default={})  # Tenant-specific settings (thresholds, etc.)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Tenant(tenant_id={self.tenant_id}, name={self.name})>"


class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = 'users'

    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=False, default='default', index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default='analyst', index=True)  # analyst, admin, superadmin
    is_superadmin = Column(Boolean, default=False, index=True)
    functionalities = Column(JSON, default=[])  # Permissions list
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User(username={self.username}, role={self.role})>"


class ManagedDevice(Base):
    """
    Formally registered device/asset for a tenant.
    Used for authoritative identification, health monitoring, and auto-allowlisting.
    """
    __tablename__ = 'managed_devices'

    id = Column(PortableBigInt, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=False, default='default', index=True)
    name = Column(String(128), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    device_id = Column(String(100), index=True, nullable=True) # For correlation with logs
    category = Column(String(32), default='other') # firewall, switch, server, endpoint, waf
    status = Column(String(20), default='active') # active, maintenance, retired
    
    # Metadata
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_log_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index('idx_managed_dev_tenant_ip', 'tenant_id', 'ip_address'),
        Index('idx_managed_dev_tenant_id_corr', 'tenant_id', 'device_id'),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "ip_address": self.ip_address,
            "device_id": self.device_id,
            "category": self.category,
            "status": self.status,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_log_at": self.last_log_at.isoformat() if self.last_log_at else None
        }
