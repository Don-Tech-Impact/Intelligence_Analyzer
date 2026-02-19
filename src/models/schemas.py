from pydantic import BaseModel, Field, IPvAnyAddress, validator
from typing import Optional, Any, Dict, List, Generic, TypeVar
from datetime import datetime

T = TypeVar('T')

class ApiResponse(BaseModel, Generic[T]):
    """Standard API response envelope."""
    status: str = "success"
    data: Optional[T] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class NormalizedLogSchema(BaseModel):
    """Schema for a normalized log entry."""
    company_id: Optional[str] = Field(default=None, description="The top-level business entity")
    tenant_id: str = Field(default='default', description="The specific branch or subdivision")
    device_id: Optional[str] = Field(default=None, description="The specific source device or service")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    log_type: str = Field(default='generic')
    vendor: Optional[str] = None
    device_hostname: Optional[str] = None
    severity: Optional[str] = 'low'
    message: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    business_context: Dict[str, Any] = Field(default_factory=dict)

    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                return datetime.utcnow()
        return v

class AlertUpdateSchema(BaseModel):
    status: str = Field(..., description="The status of the alert (e.g., acknowledged, resolved, closed)")
    analyst_comment: Optional[str] = None

class DashboardSummarySchema(BaseModel):
    tenant_id: str
    stats: Dict[str, Any]
    trends: Dict[str, Any]
    top_ips: Dict[str, Any]
    protocols: List[Dict[str, Any]]
    recent_alerts: List[Dict[str, Any]]
    business_insights: Dict[str, Any]
    intelligence: Dict[str, Any] = Field(default_factory=dict)

class UserBase(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    role: str = 'business'
    tenant_id: str = 'default'

class UserCreate(UserBase):
    password: str
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('passwords do not match')
        return v

class UserResponse(UserBase):
    id: int
    is_active: bool
    username: str   
    business_details: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True
