# SIEM Analyzer - Quick Start Guide

## Prerequisites

Before you begin, ensure you have:
- Python 3.9 or higher installed
- Redis server running (for log ingestion)
- Basic understanding of security logs

## Installation Steps

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/Don-Tech-Impact/Intelligence_Analyzer.git
cd Intelligence_Analyzer

# Install dependencies
pip install -r requirements.txt

# Run setup script
python scripts/setup.py
```

### 2. Configuration

Edit `config/config.yaml` to customize your settings:

```yaml
database:
  type: sqlite  # or postgresql for production
  
redis:
  host: localhost
  port: 6379
  log_queue: "siem:logs"
  
email:
  enabled: false  # Set to true to enable email alerts
  smtp:
    host: smtp.gmail.com
    port: 587
    user: your-email@gmail.com
    password: your-app-password
```

For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833).

### 3. Start Redis (if not running)

```bash
# On Linux/Mac
redis-server

# On Docker
docker run -d -p 6379:6379 redis:latest
```

### 4. Run the Analyzer

```bash
python -m src.main
```

You should see:
```
============================================================
SIEM Analyzer Starting
============================================================
INFO - Initializing SIEM Analyzer
INFO - Database initialized successfully
INFO - Registered analyzer: brute_force
INFO - Registered analyzer: port_scan
INFO - Registered analyzer: threat_intel
INFO - Starting Redis consumer on queue: siem:logs
INFO - SIEM Analyzer started successfully
```

## Testing the System

### Send Test Logs

In a new terminal, run the test log generator:

```bash
python scripts/send_test_logs.py
```

Choose from:
1. Send random logs
2. Simulate brute force attack
3. Simulate port scan
4. Run all scenarios

### View Results

Check the database for logs and alerts:

```bash
# Show statistics
python scripts/query_db.py stats

# List recent alerts
python scripts/query_db.py alerts --limit 20

# Show top source IPs
python scripts/query_db.py top-ips --limit 10

# Search specific logs
python scripts/query_db.py search --source-ip 192.168.1.100
```

### Check Log Files

```bash
# View application logs
tail -f logs/siem_analyzer.log

# Parse JSON logs
cat logs/siem_analyzer.log | python -m json.tool
```

## Log Format

Send logs to Redis in JSON format:

```python
import redis
import json

r = redis.Redis(host='localhost', port=6379, db=0)

log = {
    'timestamp': '2025-10-23T10:30:00Z',
    'source_ip': '192.168.1.100',
    'destination_ip': '10.0.0.50',
    'source_port': 54321,
    'destination_port': 22,
    'protocol': 'TCP',
    'action': 'failed',
    'log_type': 'auth',
    'message': 'SSH authentication failed'
}

r.rpush('siem:logs', json.dumps(log))
```

## Expected Alerts

### Brute Force Detection
Triggers when 5+ failed authentication attempts occur within 300 seconds from the same source IP.

**Example:**
```
[HIGH] brute_force
Source IP: 192.168.1.100
Description: Brute force attack detected from 192.168.1.100. 
10 failed authentication attempts in 300 seconds.
```

### Port Scan Detection
Triggers when 10+ unique ports are accessed within 60 seconds.

**Example:**
```
[MEDIUM] port_scan
Source IP: 192.168.1.101
Description: Port scan detected from 192.168.1.101 to 10.0.0.10. 
15 unique ports accessed in 60 seconds.
```

### Threat Intelligence Match
Triggers when an IP matches known threat indicators.

**Example:**
```
[HIGH] threat_intel
Source IP: 203.0.113.10
Description: Threat intelligence match: 203.0.113.10 (source IP) 
is known malicious. Source: abuse_ch
```

## Viewing Reports

Reports are generated automatically based on your schedule:

```bash
# List generated reports
ls -lh reports/

# View HTML report in browser
firefox reports/daily_report_20251023_090000.html
```

## Troubleshooting

### Redis Connection Error
```
Error: Could not connect to Redis
```
**Solution:** Ensure Redis is running on the configured host and port.

```bash
redis-cli ping  # Should return PONG
```

### Database Issues
```
Error: Database initialization failed
```
**Solution:** Check database configuration and permissions.

```bash
# Reinitialize database
python scripts/setup.py
```

### No Alerts Generated
**Check:**
1. Logs are being consumed (check log file)
2. Detection thresholds are appropriate
3. Log format matches expected schema

### Email Alerts Not Sending
**Check:**
1. `email.enabled: true` in config
2. SMTP credentials are correct
3. Test SMTP connection:

```python
from src.services.email_alert import EmailAlertService
service = EmailAlertService()
service.test_connection()
```

## Next Steps

1. **Integrate with your log sources** - Configure your systems to send logs to Redis
2. **Customize detection rules** - Adjust thresholds in `config/config.yaml`
3. **Set up email alerts** - Configure SMTP settings for notifications
4. **Add threat feeds** - Configure additional threat intelligence sources
5. **Create custom analyzers** - Develop analyzers for specific threats

## Production Deployment

### Use PostgreSQL

```yaml
database:
  type: postgresql
  host: db.example.com
  port: 5432
  name: siem_production
  user: siem_user
  password: secure_password
```

### Enable Email Alerts

```yaml
email:
  enabled: true
  smtp:
    host: smtp.company.com
    port: 587
    user: siem@company.com
    password: ${SMTP_PASSWORD}
  to:
    - security-team@company.com
```

### Run as Service

Create a systemd service file `/etc/systemd/system/siem-analyzer.service`:

```ini
[Unit]
Description=SIEM Analyzer
After=network.target redis.service

[Service]
Type=simple
User=siem
WorkingDirectory=/opt/Intelligence_Analyzer
ExecStart=/usr/bin/python3 -m src.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable siem-analyzer
sudo systemctl start siem-analyzer
sudo systemctl status siem-analyzer
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/Don-Tech-Impact/Intelligence_Analyzer/issues
- Documentation: See README.md

## Security Notes

- Never commit `.env` files with credentials
- Use environment variables for sensitive data
- Regularly update threat intelligence feeds
- Review and tune detection thresholds
- Monitor system performance and disk usage
