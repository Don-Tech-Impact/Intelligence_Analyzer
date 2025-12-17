from pydantic import BaseModel, Field, IPvAnyAddress, validator
from typing import Optional, Any, Dict
from datetime import datetime

class NormalizedLogSchema(BaseModel):
    """Schema for a normalized log entry."""
    tenant_id: str = Field(default='default')
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    log_type: str = Field(default='generic')
    message: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)

    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                # Attempt to parse ISO format
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                # Fallback to current time if parsing fails
                return datetime.utcnow()
        return v
