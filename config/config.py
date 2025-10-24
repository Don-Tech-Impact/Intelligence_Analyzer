from pydantic_settings import BaseSettings
from pydantic import Field, RedisDsn, PostgresDsn
from typing import Optional, List
import os

class RedisSettings(BaseSettings):
    host: str = Field(default="localhost", description="Redis server host")
    port: int = Field(default=6379, description="Redis server port")
    db: int = Field(default=0, description="Redis database number")
    password: Optional[str] = Field(default=None, description="Redis password")
    
    @property
    def url(self) -> str:
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"

class DatabaseSettings(BaseSettings):
    url: PostgresDsn = Field(
        default="postgresql://user:pass@localhost/siem",
        description="Database connection URL"
    )
    echo: bool = Field(default=False, description="SQLAlchemy echo mode")

class EmailSettings(BaseSettings):
    smtp_server: str = Field(default="smtp.gmail.com")
    smtp_port: int = Field(default=587)
    email_user: str = Field(default="alerts@company.com")
    email_password: str = Field(...)  # Required field
    from_email: str = Field(default="siem-alerts@company.com")
    to_emails: List[str] = Field(default=["security@company.com"])

class AnalysisSettings(BaseSettings):
    brute_force_threshold: int = Field(default=5, description="Failed logins per minute")
    port_scan_threshold: int = Field(default=10, description="Ports scanned per minute")
    after_hours_start: str = Field(default="18:00", description="After hours start (24h)")
    after_hours_end: str = Field(default="06:00", description="After hours end (24h)")
    threat_intel_api_key: Optional[str] = Field(default=None)

class Settings(BaseSettings):
    redis: RedisSettings = RedisSettings()
    database: DatabaseSettings = DatabaseSettings()
    email: EmailSettings = EmailSettings()
    analysis: AnalysisSettings = AnalysisSettings()
    
    log_level: str = Field(default="INFO")
    organization_id: str = Field(default="default")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"  # Allows REDIS__HOST, REDIS__PORT

# Global settings instance
settings = Settings()