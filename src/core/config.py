# config.py ─ Pydantic v2 rewrite
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, computed_field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

# ─── .env loading (same precedence as original) ───────────────────────────────
_project_root = Path(__file__).parents[2]
for _env_path in [
    _project_root / ".env",
    _project_root / "config" / ".env.production",
    _project_root / "config" / ".env.development",
]:
    if _env_path.exists():
        load_dotenv(_env_path)
        break


# ─── Custom YAML settings source ──────────────────────────────────────────────
class YamlConfigSource(PydanticBaseSettingsSource):
    """Loads settings from a YAML file. Lowest priority — env vars override it."""

    def get_field_value(self, field: Any, field_name: str) -> Any:
        return None  # handled in __call__

    def __call__(self) -> Dict[str, Any]:
        config_path = os.getenv("CONFIG_PATH", "config/config.yaml")
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file) as f:
                return yaml.safe_load(f) or {}
        return {}


# ─── Nested sub-models ────────────────────────────────────────────────────────


class DatabaseSettings(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    type: str = "sqlite"
    url: Optional[str] = None
    host: str = "localhost"
    port: int = 5432
    name: str = "siem_analyzer"
    user: str = "admin"
    password: str = "password"

    @computed_field
    @property
    def resolved_type(self) -> str:
        raw = os.getenv("DATABASE_URL", "")
        if raw.startswith("postgresql"):
            return "postgresql"
        if raw.startswith("sqlite"):
            return "sqlite"
        return self.type

    @computed_field
    @property
    def database_url(self) -> str:
        env_url = os.getenv("DATABASE_URL")
        if env_url:
            return env_url
        if self.url:
            return self.url
        if self.resolved_type == "postgresql":
            host = os.getenv("POSTGRES_HOST") or self.host
            port = os.getenv("POSTGRES_PORT") or str(self.port)
            name = os.getenv("POSTGRES_DB") or self.name
            user = os.getenv("POSTGRES_USER") or self.user
            pwd = os.getenv("POSTGRES_PASSWORD") or self.password
            return f"postgresql://{user}:{pwd}@{host}:{port}/{name}"
        if self.resolved_type == "sqlite":
            return f"sqlite:///{self.name}.db"
        raise ValueError(f"Unsupported database type: {self.resolved_type}")


class RedisSettings(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    url: Optional[str] = None
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    queue_pattern: str = "logs:*"
    queue_scan_interval: int = 30
    ingest_queue: str = "ingest_logs"
    clean_queue: str = "clean_logs"
    dead_queue: str = "dead_logs"

    @computed_field
    @property
    def redis_url(self) -> str:
        env_url = os.getenv("REDIS_URL")
        if env_url:
            return env_url
        if self.url:
            return self.url
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{host}:{self.port}/{self.db}"


class SmtpSettings(BaseModel):
    host: str = "smtp.gmail.com"
    port: int = 587
    user: str = ""
    password: str = ""
    use_tls: bool = True


class EmailSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    enabled: bool = False
    smtp: SmtpSettings = Field(default_factory=SmtpSettings)
    from_address: str = Field("siem-alerts@company.com", alias="from")
    to: List[str] = Field(default_factory=lambda: ["security-team@company.com"])


class BruteForceSettings(BaseModel):
    threshold: int = 5
    time_window: int = 300


class PortScanSettings(BaseModel):
    threshold: int = 10
    time_window: int = 60


class DetectionSettings(BaseModel):
    brute_force: BruteForceSettings = Field(default_factory=BruteForceSettings)
    port_scan: PortScanSettings = Field(default_factory=PortScanSettings)


class ThreatIntelSettings(BaseModel):
    enabled: bool = True
    update_interval: int = 3600
    feeds: List[Any] = Field(default_factory=list)


class ReportingSettings(BaseModel):
    enabled: bool = True
    schedule: str = "0 9 * * *"
    email_to: List[str] = Field(default_factory=lambda: ["reports@company.com"])


class WebhookSettings(BaseModel):
    enabled: bool = False
    discord: str = ""
    slack: str = ""


class LoggingSettings(BaseModel):
    level: str = "INFO"
    file: str = "logs/siem_analyzer.log"
    max_bytes: int = 10_485_760
    backup_count: int = 5


class MultiTenantSettings(BaseModel):
    enabled: bool = False
    default_tenant: str = "default"
    tenants: List[Any] = Field(default_factory=list)


# ─── Root settings (env vars take priority over YAML) ─────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="__",  # REDIS__QUEUE_PATTERN → redis.queue_pattern
        populate_by_name=True,
        extra="ignore",
    )

    # Top-level secrets
    secret_key: str = "fallback-secret-key-for-diagnostic-suffix"
    admin_api_key: str = "changeme-admin-key"
    jwt_public_key: Optional[str] = None
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    repo1_url: Optional[str] = None
    repo1_base_url: str = "http://ingestion-api:8080"

    # Nested sections
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    threat_intelligence: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    webhooks: WebhookSettings = Field(default_factory=WebhookSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    multi_tenant: MultiTenantSettings = Field(default_factory=MultiTenantSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        # Priority order: init kwargs → env vars → YAML file
        return (init_settings, env_settings, YamlConfigSource(settings_cls))

    # ── Parsed list properties ────────────────────────────────────────────────
    @computed_field
    @property
    def parsed_allowed_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @computed_field
    @property
    def parsed_allowed_hosts(self) -> List[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    @computed_field
    @property
    def effective_repo1_url(self) -> str:
        """Returns the fully qualified URL for Repo 1 based on environment."""
        return str(self.repo1_url or self.repo1_base_url).strip().rstrip("/")

    # ── Backward-compatible shortcuts (keeps all original call sites working) ─
    @property
    def database_type(self) -> str:
        return self.database.resolved_type

    @property
    def database_url(self) -> str:
        return self.database.database_url

    @property
    def redis_url(self) -> str:
        return self.redis.redis_url

    @property
    def redis_host(self) -> str:
        return self.redis.host

    @property
    def redis_port(self) -> int:
        return self.redis.port

    @property
    def redis_queue_pattern(self) -> str:
        return self.redis.queue_pattern

    @property
    def redis_queue_scan_interval(self) -> int:
        return self.redis.queue_scan_interval

    @property
    def redis_ingest_queue(self) -> str:
        return self.redis.ingest_queue

    @property
    def redis_clean_queue(self) -> str:
        return self.redis.clean_queue

    @property
    def redis_dead_queue(self) -> str:
        return self.redis.dead_queue

    @property
    def email_enabled(self) -> bool:
        return self.email.enabled

    @property
    def smtp_host(self) -> str:
        return self.email.smtp.host

    @property
    def smtp_port(self) -> int:
        return self.email.smtp.port

    @property
    def smtp_user(self) -> str:
        return self.email.smtp.user

    @property
    def smtp_password(self) -> str:
        return self.email.smtp.password

    @property
    def smtp_use_tls(self) -> bool:
        return self.email.smtp.use_tls

    @property
    def email_from(self) -> str:
        return self.email.from_address

    @property
    def email_to(self) -> List[str]:
        return self.email.to

    @property
    def brute_force_threshold(self) -> int:
        return self.detection.brute_force.threshold

    @property
    def brute_force_time_window(self) -> int:
        return self.detection.brute_force.time_window

    @property
    def port_scan_threshold(self) -> int:
        return self.detection.port_scan.threshold

    @property
    def port_scan_time_window(self) -> int:
        return self.detection.port_scan.time_window

    @property
    def threat_intel_enabled(self) -> bool:
        return self.threat_intelligence.enabled

    @property
    def threat_intel_update_interval(self) -> int:
        return self.threat_intelligence.update_interval

    @property
    def threat_intel_feeds(self) -> list:
        return self.threat_intelligence.feeds

    @property
    def report_enabled(self) -> bool:
        return self.reporting.enabled

    @property
    def report_schedule(self) -> str:
        return self.reporting.schedule

    @property
    def report_email_to(self) -> list:
        return self.reporting.email_to

    @property
    def webhooks_enabled(self) -> bool:
        return self.webhooks.enabled

    @property
    def discord_webhook_url(self) -> str:
        return self.webhooks.discord

    @property
    def slack_webhook_url(self) -> str:
        return self.webhooks.slack

    @property
    def log_level(self) -> str:
        return self.logging.level

    @property
    def log_file(self) -> str:
        return self.logging.file

    @property
    def log_max_bytes(self) -> int:
        return self.logging.max_bytes

    @property
    def log_backup_count(self) -> int:
        return self.logging.backup_count

    @property
    def multi_tenant_enabled(self) -> bool:
        return self.multi_tenant.enabled

    @property
    def default_tenant(self) -> str:
        return self.multi_tenant.default_tenant

    @property
    def tenants(self) -> list:
        return self.multi_tenant.tenants

    @property
    def admin_api_key(self) -> str:
        return self.ADMIN_KEY

    # ── Persistence ───────────────────────────────────────────────────────────
    def save(self, config_path: Optional[str] = None) -> None:
        """Serialize current settings to YAML, stripping computed fields."""
        path = Path(config_path or os.getenv("CONFIG_PATH", "config/config.yaml"))
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(exclude={"parsed_allowed_origins", "parsed_allowed_hosts", "effective_repo1_url"})
        data["database"].pop("database_url", None)
        data["database"].pop("resolved_type", None)
        data["redis"].pop("redis_url", None)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)

    def set(self, key: str, value: Any) -> None:
        """Update a nested setting via dot-notation, then persist.

        Example: config.set("redis.queue_pattern", "events:*")
        """
        parts = key.split(".")
        target: Any = self
        for part in parts[:-1]:
            target = getattr(target, part)
        setattr(target, parts[-1], value)
        self.save()


config = Settings()
