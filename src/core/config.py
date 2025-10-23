"""Configuration management for SIEM Analyzer."""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dotenv import load_dotenv


class Config:
    """Configuration manager that loads settings from YAML and environment variables."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self._config: Dict[str, Any] = {}
        
        # Load environment variables
        load_dotenv()
        
        # Load YAML configuration
        if config_path is None:
            config_path = os.getenv('CONFIG_PATH', 'config/config.yaml')
        
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                self._config = yaml.safe_load(f) or {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with support for nested keys.
        
        Args:
            key: Configuration key (supports dot notation: 'database.host')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        # Check environment variable first (convert dot notation to underscore uppercase)
        env_key = key.upper().replace('.', '_')
        env_value = os.getenv(env_key)
        if env_value is not None:
            return self._cast_value(env_value)
        
        # Navigate nested dictionary
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        
        return value
    
    def _cast_value(self, value: str) -> Any:
        """Cast string value to appropriate type."""
        # Boolean
        if value.lower() in ('true', 'yes', '1'):
            return True
        if value.lower() in ('false', 'no', '0'):
            return False
        
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        
        return value
    
    # Database configuration
    @property
    def database_type(self) -> str:
        return self.get('database.type', 'sqlite')
    
    @property
    def database_url(self) -> str:
        """Get SQLAlchemy database URL."""
        db_type = self.database_type
        
        if db_type == 'sqlite':
            db_name = self.get('database.name', 'siem_analyzer')
            return f'sqlite:///{db_name}.db'
        
        elif db_type == 'postgresql':
            host = self.get('database.host', 'localhost')
            port = self.get('database.port', 5432)
            name = self.get('database.name', 'siem_analyzer')
            user = self.get('database.user', 'admin')
            password = self.get('database.password', 'password')
            return f'postgresql://{user}:{password}@{host}:{port}/{name}'
        
        raise ValueError(f'Unsupported database type: {db_type}')
    
    # Redis configuration
    @property
    def redis_host(self) -> str:
        return self.get('redis.host', 'localhost')
    
    @property
    def redis_port(self) -> int:
        return self.get('redis.port', 6379)
    
    @property
    def redis_db(self) -> int:
        return self.get('redis.db', 0)
    
    @property
    def redis_password(self) -> Optional[str]:
        pwd = self.get('redis.password', '')
        return pwd if pwd else None
    
    @property
    def redis_log_queue(self) -> str:
        return self.get('redis.log_queue', 'siem:logs')
    
    @property
    def redis_alert_queue(self) -> str:
        return self.get('redis.alert_queue', 'siem:alerts')
    
    # Email configuration
    @property
    def email_enabled(self) -> bool:
        return self.get('email.enabled', False)
    
    @property
    def smtp_host(self) -> str:
        return self.get('email.smtp.host', 'smtp.gmail.com')
    
    @property
    def smtp_port(self) -> int:
        return self.get('email.smtp.port', 587)
    
    @property
    def smtp_user(self) -> str:
        return self.get('email.smtp.user', '')
    
    @property
    def smtp_password(self) -> str:
        return self.get('email.smtp.password', '')
    
    @property
    def smtp_use_tls(self) -> bool:
        return self.get('email.smtp.use_tls', True)
    
    @property
    def email_from(self) -> str:
        return self.get('email.from', 'siem-alerts@company.com')
    
    @property
    def email_to(self) -> list:
        return self.get('email.to', ['security-team@company.com'])
    
    # Detection configuration
    @property
    def brute_force_threshold(self) -> int:
        return self.get('detection.brute_force.threshold', 5)
    
    @property
    def brute_force_time_window(self) -> int:
        return self.get('detection.brute_force.time_window', 300)
    
    @property
    def port_scan_threshold(self) -> int:
        return self.get('detection.port_scan.threshold', 10)
    
    @property
    def port_scan_time_window(self) -> int:
        return self.get('detection.port_scan.time_window', 60)
    
    # Threat Intelligence configuration
    @property
    def threat_intel_enabled(self) -> bool:
        return self.get('threat_intelligence.enabled', True)
    
    @property
    def threat_intel_update_interval(self) -> int:
        return self.get('threat_intelligence.update_interval', 3600)
    
    @property
    def threat_intel_feeds(self) -> list:
        return self.get('threat_intelligence.feeds', [])
    
    # Reporting configuration
    @property
    def report_enabled(self) -> bool:
        return self.get('reporting.enabled', True)
    
    @property
    def report_schedule(self) -> str:
        return self.get('reporting.schedule', '0 9 * * *')
    
    @property
    def report_email_to(self) -> list:
        return self.get('reporting.email_to', ['reports@company.com'])
    
    # Logging configuration
    @property
    def log_level(self) -> str:
        return self.get('logging.level', 'INFO')
    
    @property
    def log_file(self) -> str:
        return self.get('logging.file', 'logs/siem_analyzer.log')
    
    @property
    def log_max_bytes(self) -> int:
        return self.get('logging.max_bytes', 10485760)
    
    @property
    def log_backup_count(self) -> int:
        return self.get('logging.backup_count', 5)
    
    # Multi-tenant configuration
    @property
    def multi_tenant_enabled(self) -> bool:
        return self.get('multi_tenant.enabled', False)
    
    @property
    def default_tenant(self) -> str:
        return self.get('multi_tenant.default_tenant', 'default')
    
    @property
    def tenants(self) -> list:
        return self.get('multi_tenant.tenants', [])


# Global configuration instance
config = Config()
