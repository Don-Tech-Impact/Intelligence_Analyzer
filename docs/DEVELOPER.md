# SIEM Analyzer - Developer Guide

## Architecture Overview

The SIEM Analyzer follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Main Application                      │
│                      (src/main.py)                       │
└───────────────────┬─────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│  Redis   │  │ Analyzer │  │Scheduler │
│ Consumer │  │ Manager  │  │          │
└─────┬────┘  └────┬─────┘  └────┬─────┘
      │            │             │
      ▼            ▼             ▼
┌──────────────────────────────────────┐
│          Database (SQLAlchemy)        │
│  - Logs  - Alerts  - Threat Intel    │
└──────────────────────────────────────┘
```

## Core Components

### 1. Configuration System

**Location:** `src/core/config.py`

The configuration system supports both YAML files and environment variables.

```python
from src.core.config import config

# Access configuration values
redis_host = config.redis_host
db_url = config.database_url
```

**Priority:** Environment Variables > YAML Configuration

### 2. Database Layer

**Location:** `src/core/database.py`, `src/models/database.py`

All database operations use SQLAlchemy ORM with context managers:

```python
from src.core.database import db_manager
from src.models.database import Log

# Initialize database
db_manager.initialize()

# Use session scope for transactions
with db_manager.session_scope() as session:
    log = Log(source_ip='192.168.1.1', ...)
    session.add(log)
    # Automatically commits on success, rolls back on error
```

### 3. Redis Consumer

**Location:** `src/services/redis_consumer.py`

Consumes logs from Redis queue and stores them in the database.

```python
from src.services.redis_consumer import RedisConsumer

consumer = RedisConsumer()
consumer.connect()
consumer.start()  # Blocking call
```

## Creating Custom Analyzers

Analyzers detect threats by examining log entries. Create a custom analyzer by extending `BaseAnalyzer`:

### Step 1: Create Analyzer Class

**File:** `src/analyzers/my_analyzer.py`

```python
from src.analyzers.base import BaseAnalyzer
from src.models.database import Log, Alert
from typing import Optional

class MyCustomAnalyzer(BaseAnalyzer):
    """Detects custom security threats."""
    
    def __init__(self):
        super().__init__('my_custom_analyzer')
        # Initialize any state or thresholds
        self.threshold = 10
    
    def analyze(self, log: Log) -> Optional[Alert]:
        """Analyze a log entry.
        
        Args:
            log: Log entry to analyze
            
        Returns:
            Alert if threat detected, None otherwise
        """
        # Your detection logic here
        if self._is_suspicious(log):
            return self.create_alert(
                alert_type='custom_threat',
                severity='high',
                source_ip=log.source_ip,
                description=f'Custom threat detected from {log.source_ip}',
                details={
                    'log_id': log.id,
                    'additional_info': 'value'
                },
                tenant_id=log.tenant_id,
                destination_ip=log.destination_ip
            )
        
        return None
    
    def _is_suspicious(self, log: Log) -> bool:
        """Helper method for detection logic."""
        # Implement your detection logic
        return False
```

### Step 2: Register Analyzer

**File:** `src/main.py`

```python
from src.analyzers.my_analyzer import MyCustomAnalyzer

def initialize(self):
    # ... existing code ...
    
    # Register custom analyzer
    analyzer_manager.register(MyCustomAnalyzer())
```

### Analyzer Methods

#### `analyze(log: Log) -> Optional[Alert]`
Main detection method. Return an Alert if a threat is detected, None otherwise.

#### `create_alert(...) -> Alert`
Helper method to create and store alerts:

```python
alert = self.create_alert(
    alert_type='threat_type',      # Custom identifier
    severity='low|medium|high|critical',
    source_ip='1.2.3.4',
    description='Human-readable description',
    details={...},                 # Additional structured data
    tenant_id='default',
    destination_ip='5.6.7.8'       # Optional
)
```

#### `enable()` / `disable()`
Control whether the analyzer is active.

## Database Models

### Log Model

```python
from src.models.database import Log

log = Log(
    tenant_id='default',
    timestamp=datetime.utcnow(),
    source_ip='192.168.1.100',
    destination_ip='10.0.0.5',
    source_port=54321,
    destination_port=22,
    protocol='TCP',
    action='failed',
    log_type='auth',
    message='Authentication failed',
    raw_data={}  # Original log data
)
```

### Alert Model

```python
from src.models.database import Alert

alert = Alert(
    tenant_id='default',
    alert_type='brute_force',
    severity='high',
    source_ip='192.168.1.100',
    destination_ip='10.0.0.5',
    description='Brute force attack detected',
    details={'attempts': 10},
    status='open',  # open, acknowledged, resolved
    notified=False
)
```

### Threat Intelligence Model

```python
from src.models.database import ThreatIntelligence

indicator = ThreatIntelligence(
    indicator_type='ip',  # ip, domain, hash, url
    indicator_value='203.0.113.10',
    threat_type='botnet',
    confidence=0.9,  # 0.0 to 1.0
    source='abuse_ch',
    description='Known botnet C2 server',
    is_active=True
)
```

## Querying Data

### Basic Queries

```python
from src.core.database import db_manager
from src.models.database import Log, Alert

with db_manager.session_scope() as session:
    # Get all open alerts
    alerts = session.query(Alert).filter(
        Alert.status == 'open'
    ).all()
    
    # Get recent logs from specific IP
    logs = session.query(Log).filter(
        Log.source_ip == '192.168.1.100',
        Log.timestamp >= some_date
    ).order_by(Log.timestamp.desc()).limit(100).all()
```

### Aggregation Queries

```python
from sqlalchemy import func

with db_manager.session_scope() as session:
    # Count alerts by severity
    results = session.query(
        Alert.severity,
        func.count(Alert.id)
    ).group_by(Alert.severity).all()
    
    # Top source IPs by alert count
    results = session.query(
        Alert.source_ip,
        func.count(Alert.id).label('count')
    ).group_by(Alert.source_ip).order_by(
        func.count(Alert.id).desc()
    ).limit(10).all()
```

## Custom Report Generation

Extend the reporting system:

```python
from src.services.report_generator import ReportGenerator
from datetime import datetime, timedelta

generator = ReportGenerator(output_dir='custom_reports')

# Generate custom report
report = generator.generate_report(
    start_date=datetime.now() - timedelta(days=7),
    end_date=datetime.now(),
    report_type='weekly',
    tenant_id='default'
)
```

## Email Notifications

Send custom email alerts:

```python
from src.services.email_alert import EmailAlertService

email_service = EmailAlertService()

# Test connection
if email_service.test_connection():
    # Send alert
    email_service.send_alert(alert_object)
```

## Scheduled Tasks

Add custom scheduled tasks:

```python
from src.services.scheduler import TaskScheduler

scheduler = TaskScheduler()

# Add custom task
scheduler.scheduler.add_job(
    func=my_custom_function,
    trigger='interval',
    minutes=30,
    id='my_task',
    name='My Custom Task'
)
```

## Testing

### Unit Tests

Create tests in the `tests/` directory:

```python
import pytest
from src.analyzers.brute_force import BruteForceAnalyzer
from src.models.database import Log

def test_brute_force_detection():
    analyzer = BruteForceAnalyzer()
    
    log = Log(
        source_ip='192.168.1.100',
        log_type='auth',
        action='failed'
    )
    
    # Should not trigger on single attempt
    alert = analyzer.analyze(log)
    assert alert is None
```

### Integration Tests

```python
def test_redis_consumer():
    from src.services.redis_consumer import RedisConsumer
    
    consumer = RedisConsumer()
    consumer.connect()
    
    # Verify connection
    assert consumer.redis_client is not None
    assert consumer.get_queue_size() >= 0
```

## Performance Considerations

### Database Optimization

1. **Use indexes** - All query-heavy columns have indexes
2. **Batch operations** - Use bulk inserts for large datasets:

```python
with db_manager.session_scope() as session:
    session.bulk_insert_mappings(Log, log_list)
```

3. **Query optimization** - Use appropriate filters and limits

### Redis Queue Management

Monitor queue size to prevent memory issues:

```python
consumer = RedisConsumer()
queue_size = consumer.get_queue_size()

if queue_size > 10000:
    # Take action: scale consumers, alert, etc.
    pass
```

## Extending Threat Intelligence

Add custom threat intelligence sources:

```python
from src.services.threat_intel_updater import ThreatIntelUpdater

class CustomThreatFeed:
    def fetch_indicators(self):
        # Fetch from your source
        return [
            {
                'type': 'ip',
                'value': '1.2.3.4',
                'threat_type': 'malware',
                'confidence': 0.8
            }
        ]

updater = ThreatIntelUpdater()
indicators = CustomThreatFeed().fetch_indicators()
updater._store_indicators(indicators, 'custom_feed')
```

## Multi-Tenant Implementation

Isolate data by tenant:

```python
# All models have tenant_id field
with db_manager.session_scope() as session:
    # Query specific tenant's data
    logs = session.query(Log).filter(
        Log.tenant_id == 'tenant1'
    ).all()
```

## Logging

Use structured logging throughout:

```python
import logging
logger = logging.getLogger(__name__)

logger.info('Processing log', extra={
    'source_ip': log.source_ip,
    'log_type': log.log_type
})
```

## Error Handling

Use proper exception handling:

```python
try:
    # Database operation
    with db_manager.session_scope() as session:
        session.add(obj)
except Exception as e:
    logger.error(f'Database error: {e}', exc_info=True)
    # Handle error appropriately
```

## Best Practices

1. **Use context managers** - Always use `session_scope()` for database operations
2. **Validate input** - Validate log data before processing
3. **Log extensively** - Use appropriate log levels
4. **Handle errors gracefully** - Don't let one bad log crash the system
5. **Test thoroughly** - Write tests for custom analyzers
6. **Monitor performance** - Track processing rates and queue sizes
7. **Document code** - Add docstrings to all functions and classes

## API Integration (Future)

While the current version doesn't expose an HTTP API, you can integrate programmatically:

```python
# Push logs programmatically
from src.services.redis_consumer import RedisConsumer
import json
import redis

r = redis.Redis(host='localhost', port=6379)
log_data = {...}
r.rpush('siem:logs', json.dumps(log_data))
```

## Debugging

Enable debug logging:

```yaml
# config/config.yaml
logging:
  level: DEBUG
```

Or use environment variable:
```bash
export LOG_LEVEL=DEBUG
```

## Support

- GitHub Issues: https://github.com/Don-Tech-Impact/Intelligence_Analyzer/issues
- Code Documentation: See inline docstrings
- Examples: See `examples/` directory
