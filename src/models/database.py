"""Database models for SIEM Analyzer."""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean, Float, 
    ForeignKey, Index, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Log(Base):
    """Log entry model."""
    __tablename__ = 'logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), default='default', index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)  # IPv4 or IPv6
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(20))
    action = Column(String(50))
    log_type = Column(String(50), index=True)
    message = Column(Text)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_tenant_timestamp', 'tenant_id', 'timestamp'),
        Index('idx_source_ip_timestamp', 'source_ip', 'timestamp'),
        Index('idx_dest_ip_timestamp', 'destination_ip', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<Log(id={self.id}, source_ip={self.source_ip}, timestamp={self.timestamp})>"


class Alert(Base):
    """Security alert model."""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), default='default', index=True)
    alert_type = Column(String(100), index=True)  # brute_force, port_scan, threat_intel
    severity = Column(String(20), index=True)  # low, medium, high, critical
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    description = Column(Text)
    details = Column(JSON)
    status = Column(String(20), default='open', index=True)  # open, acknowledged, resolved
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    notified = Column(Boolean, default=False)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_tenant_created', 'tenant_id', 'created_at'),
        Index('idx_status_severity', 'status', 'severity'),
    )
    
    def __repr__(self):
        return f"<Alert(id={self.id}, type={self.alert_type}, severity={self.severity})>"


class ThreatIntelligence(Base):
    """Threat intelligence indicator model."""
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(20), index=True)  # ip, domain, hash, url
    indicator_value = Column(String(255), unique=True, index=True)
    threat_type = Column(String(100))  # malware, botnet, phishing, etc.
    confidence = Column(Float)  # 0.0 to 1.0
    source = Column(String(100))  # Feed name
    description = Column(Text)
    metadata_json = Column('metadata', JSON)  # Use column alias to avoid reserved name
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ThreatIntelligence(type={self.indicator_type}, value={self.indicator_value})>"


class Report(Base):
    """Generated report model."""
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), default='default', index=True)
    report_type = Column(String(50))  # daily, weekly, monthly, custom
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    total_logs = Column(Integer)
    total_alerts = Column(Integer)
    alerts_by_severity = Column(JSON)
    top_source_ips = Column(JSON)
    top_alert_types = Column(JSON)
    file_path = Column(String(500))
    format = Column(String(20))  # html, csv, pdf
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Report(id={self.id}, type={self.report_type}, created_at={self.created_at})>"


class Tenant(Base):
    """Multi-tenant configuration model."""
    __tablename__ = 'tenants'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), unique=True, index=True)
    name = Column(String(255))
    description = Column(Text)
    database_schema = Column(String(100))
    is_active = Column(Boolean, default=True)
    settings = Column(JSON)  # Tenant-specific settings
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Tenant(tenant_id={self.tenant_id}, name={self.name})>"
