# Intelligence Analyzer - Python SIEM System

A comprehensive Python-based Security Information and Event Management (SIEM) system that consumes logs from Redis queues, performs real-time threat detection, and generates automated security reports.

## Features

### Core Capabilities
- **Redis Log Consumer**: Real-time log consumption from Redis queues with automatic reconnection
- **Multi-Tenant Support**: Isolated data and configurations for different tenants
- **Persistent Storage**: PostgreSQL or SQLite database with SQLAlchemy ORM
- **Comprehensive Logging**: JSON-formatted logs with rotation support

### Threat Detection Analyzers
- **Brute Force Detection**: Identifies repeated authentication failures
- **Port Scanning Detection**: Detects reconnaissance activities
- **Threat Intelligence Matching**: Cross-references IPs against threat feeds

### Alerting & Reporting
- **Email Alerts**: Automated email notifications for security incidents
- **Scheduled Reports**: Daily, weekly, or custom security reports
- **Report Formats**: HTML and CSV report generation with pandas

### Automation
- **APScheduler Integration**: Scheduled threat intelligence updates and report generation
- **Threat Feed Management**: Automatic updates from external threat intelligence sources

## Architecture

```
Intelligence_Analyzer/
├── src/
│   ├── core/              # Core functionality
│   │   ├── config.py      # Configuration management
│   │   ├── database.py    # Database session management
│   │   └── logging_config.py  # Logging setup
│   ├── models/            # Database models
│   │   └── database.py    # SQLAlchemy models
│   ├── services/          # Business logic services
│   │   ├── redis_consumer.py      # Redis log consumer
│   │   ├── email_alert.py         # Email alerting
│   │   ├── report_generator.py   # Report generation
│   │   ├── scheduler.py           # Task scheduling
│   │   └── threat_intel_updater.py # Threat intel feeds
│   ├── analyzers/         # Threat detection analyzers
│   │   ├── base.py        # Base analyzer class
│   │   ├── brute_force.py # Brute force detector
│   │   ├── port_scan.py   # Port scan detector
│   │   └── threat_intel.py # Threat intel matcher
│   └── main.py            # Application entry point
├── config/
│   ├── config.yaml        # YAML configuration
│   └── .env.example       # Environment variables template
├── logs/                  # Application logs
├── reports/               # Generated reports
└── requirements.txt       # Python dependencies
```

## Installation

### Prerequisites
- Python 3.9 or higher
- Redis server
- PostgreSQL (optional, SQLite by default)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Don-Tech-Impact/Intelligence_Analyzer.git
cd Intelligence_Analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the application:
```bash
cp config/.env.example config/.env
# Edit config/.env with your settings
```

4. Initialize the database:
```bash
python -c "from src.core.database import db_manager; from src.core.config import config; db_manager.initialize()"
```

## Configuration

### Environment Variables
Key configuration options (see `config/.env.example`):

```bash
# Database
DATABASE_TYPE=sqlite  # or postgresql
DATABASE_NAME=siem_analyzer

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_LOG_QUEUE=siem:logs

# Email Alerts
EMAIL_ENABLED=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

# Detection Thresholds
BRUTE_FORCE_THRESHOLD=5
PORT_SCAN_THRESHOLD=10
```

### YAML Configuration
More detailed settings in `config/config.yaml`:
- Database connection details
- Redis queue names
- Email templates
- Detection parameters
- Threat intelligence feeds
- Report schedules

## Usage

### Running the SIEM Analyzer

Start the main application:
```bash
python -m src.main
```

The application will:
1. Initialize the database
2. Connect to Redis
3. Register threat analyzers
4. Start the scheduler for automated tasks
5. Begin consuming logs from Redis

### Sending Logs to Redis

Logs should be sent to the configured Redis queue as JSON:

```python
import redis
import json

r = redis.Redis(host='localhost', port=6379, db=0)

log_entry = {
    'tenant_id': 'default',
    'timestamp': '2025-10-23T10:30:00Z',
    'source_ip': '192.168.1.100',
    'destination_ip': '10.0.0.50',
    'source_port': 54321,
    'destination_port': 22,
    'protocol': 'TCP',
    'action': 'failed',
    'log_type': 'auth',
    'message': 'SSH authentication failed for user admin'
}

r.rpush('siem:logs', json.dumps(log_entry))
```

### Log Entry Schema

Required fields:
- `source_ip`: Source IP address
- `destination_ip`: Destination IP address
- `log_type`: Type of log (auth, network, firewall, etc.)

Optional fields:
- `tenant_id`: Multi-tenant identifier (default: 'default')
- `timestamp`: ISO format timestamp
- `source_port`: Source port number
- `destination_port`: Destination port number
- `protocol`: Network protocol (TCP, UDP, etc.)
- `action`: Action taken (allow, deny, failed, etc.)
- `message`: Human-readable message
- `raw_data`: Additional structured data

## Threat Detection

### Brute Force Detection
Monitors authentication failures and triggers alerts when threshold is exceeded within time window.

**Configuration:**
- `BRUTE_FORCE_THRESHOLD`: Number of failures (default: 5)
- `BRUTE_FORCE_TIME_WINDOW`: Time window in seconds (default: 300)

### Port Scanning Detection
Identifies when a source IP accesses multiple unique ports on a destination.

**Configuration:**
- `PORT_SCAN_THRESHOLD`: Number of unique ports (default: 10)
- `PORT_SCAN_TIME_WINDOW`: Time window in seconds (default: 60)

### Threat Intelligence
Matches source/destination IPs against known malicious indicators.

**Configuration:**
- `THREAT_INTEL_ENABLED`: Enable/disable (default: true)
- `THREAT_INTEL_UPDATE_INTERVAL`: Update frequency in seconds (default: 3600)

## Reporting

### Automated Reports
Daily reports are generated automatically based on the schedule in configuration.

### Manual Report Generation
```python
from src.services.report_generator import ReportGenerator
from datetime import datetime, timedelta

generator = ReportGenerator()
report = generator.generate_daily_report(
    date=datetime.now().date() - timedelta(days=1)
)
```

Reports include:
- Total logs and alerts
- Alerts by severity
- Top alert types
- Top source IPs
- Trend analysis

## Multi-Tenant Support

Enable multi-tenant mode in configuration:

```yaml
multi_tenant:
  enabled: true
  tenants:
    - name: tenant1
      database_schema: tenant1
    - name: tenant2
      database_schema: tenant2
```

Each tenant's data is isolated in the database.

## Database Schema

### Tables
- **logs**: Raw log entries
- **alerts**: Generated security alerts
- **threat_intelligence**: Threat indicators
- **reports**: Generated report metadata
- **tenants**: Multi-tenant configuration

## Development

### Running Tests
```bash
pytest tests/
```

### Adding Custom Analyzers

1. Create a new analyzer class:
```python
from src.analyzers.base import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__('custom')
    
    def analyze(self, log):
        # Your detection logic
        if condition_met:
            return self.create_alert(
                alert_type='custom_threat',
                severity='high',
                source_ip=log.source_ip,
                description='Custom threat detected',
                details={},
                tenant_id=log.tenant_id
            )
        return None
```

2. Register in `src/main.py`:
```python
analyzer_manager.register(CustomAnalyzer())
```

## Technology Stack

- **Python 3.9+**: Core programming language
- **Redis**: Message queue for log ingestion
- **SQLAlchemy 2.0+**: ORM and database abstraction
- **PostgreSQL/SQLite**: Data persistence
- **Pandas**: Data analysis and reporting
- **APScheduler**: Task scheduling
- **redis-py**: Redis client
- **pydantic**: Data validation
- **PyYAML**: Configuration management

## Monitoring

### Application Logs
Logs are written to:
- Console: Standard output with formatting
- File: `logs/siem_analyzer.log` (JSON format with rotation)

### Metrics
Monitor these key metrics:
- Redis queue size
- Log processing rate
- Alert generation rate
- Database query performance

## Troubleshooting

### Redis Connection Issues
```bash
# Test Redis connectivity
redis-cli -h localhost -p 6379 ping
```

### Database Initialization
```bash
# Reinitialize database
python -c "from src.core.database import db_manager; db_manager.initialize()"
```

### Email Alerts Not Sending
1. Check SMTP configuration
2. Test SMTP connection:
```python
from src.services.email_alert import EmailAlertService
service = EmailAlertService()
service.test_connection()
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

See LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: https://github.com/Don-Tech-Impact/Intelligence_Analyzer/issues
- Documentation: See inline code documentation

## Roadmap

- [ ] Web dashboard for visualization
- [ ] Additional analyzers (DDoS, data exfiltration)
- [ ] Machine learning-based anomaly detection
- [ ] Elasticsearch integration
- [ ] REST API for external integrations
- [ ] Kubernetes deployment manifests
