# COMPLETE ALERT LIFECYCLE: FROM LOG TO NOTIFICATION

## Overview

This document traces a **single malicious log** through the entire Repo2 SIEM system, from ingestion to alert generation. Understanding this flow is critical for debugging, optimization, and security validation.

---

## Scenario: Brute Force SSH Attack

**Attacker:** 203.0.113.50 (External IP)  
**Target:** 192.168.1.10:22 (Internal SSH Server)  
**Attack:** 6 failed SSH login attempts in 2 minutes  
**Expected Result:** Brute Force alert generated

---

## STEP 1: Log Arrives from Repo1

### 1.1 Redis Queue State

**Queue:** `logs:central-uni:clean`  
**Message Count:** 1 new message

**Raw v2.0 Log (from Repo1):**
```json
{
  "schema_version": "v2.0",
  "log_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "tenant_id": "central-uni",
  "vendor": "fortinet",
  
  "event": {
    "timestamp": "2026-02-08T14:30:05Z",
    "category": "authentication",
    "action": "deny",
    "outcome": "failure",
    "severity": "high"
  },
  
  "source": {
    "ip": "203.0.113.50",
    "port": 52341,
    "user": "admin"
  },
  
  "destination": {
    "ip": "192.168.1.10",
    "port": 22,
    "service": "ssh"
  },
  
  "network": {
    "protocol": "tcp",
    "direction": "inbound"
  },
  
  "device": {
    "hostname": "FW-01",
    "vendor": "fortinet",
    "role": "firewall"
  },
  
  "business_context": {
    "is_business_hour": true,
    "day_of_week": "Thursday",
    "is_weekend": false
  },
  
  "raw": {
    "message": "date=2026-02-08 time=14:30:05 devname=\"FW-01\" logid=\"0100032001\" type=\"event\" subtype=\"user\" level=\"warning\" srcip=203.0.113.50 dstip=192.168.1.10 action=\"deny\" msg=\"Authentication failed for user admin\""
  }
}
```

---

## STEP 2: Consumer Receives Log

### 2.1 Queue Polling

**File:** `src/services/redis_consumer.py`  
**Function:** `start()` → main event loop

```python
# Consumer polls multiple queues with BLPOP
result = self.redis_client.blpop(
    ['logs:central-uni:ingest', 'logs:central-uni:clean', 'logs:central-uni:dead'],
    timeout=1
)

# Returns: ('logs:central-uni:clean', '{"schema_version": "v2.0", ...}')
queue_name, raw_message = result
```

### 2.2 Message Routing

```python
# process_message() routes to correct handler
queue_type = queue_name.split(':')[-1]  # "clean"

if queue_type == "clean":
    self._handle_clean_log(json.loads(raw_message))
elif queue_type == "ingest":
    self._handle_ingest_log(json.loads(raw_message))
elif queue_type == "dead":
    self._handle_dead_log(json.loads(raw_message))
```

---

## STEP 3: Schema Adaptation

### 3.1 LogAdapter.normalize()

**File:** `src/services/log_adapter.py`  
**Function:** `normalize()` → `_normalize_v2()`

```python
# _handle_clean_log calls:
normalized = self.log_adapter.normalize(log_data)

# LogAdapter detects v2.0 format:
schema_version = log_data.get('schema_version', '')  # "v2.0"
if schema_version.startswith('v2.'):
    return LogAdapter._normalize_v2(log_data)
```

### 3.2 Field Extraction

```python
# _normalize_v2() extracts nested fields:
event = log.get('event', {})
source = log.get('source', {})
destination = log.get('destination', {})

return NormalizedLogSchema(
    tenant_id="central-uni",
    timestamp=datetime(2026, 2, 8, 14, 30, 5),
    source_ip="203.0.113.50",        # ✅ From log["source"]["ip"]
    source_port=52341,
    destination_ip="192.168.1.10",   # ✅ From log["destination"]["ip"]
    destination_port=22,
    protocol="tcp",
    action="deny",                    # ✅ From log["event"]["action"]
    log_type="authentication",        # ✅ From log["event"]["category"]
    severity="high",
    vendor="fortinet",
    device_hostname="FW-01",
    message="date=2026-02-08 time=14:30:05 ... msg=\"Authentication failed\"",
    raw_data={...},  # Full original log
    business_context={"is_business_hour": True, "day_of_week": "Thursday"}
)
```

### 3.3 Resulting Log Dict

```python
log_dict = {
    'tenant_id': 'central-uni',
    'timestamp': datetime(2026, 2, 8, 14, 30, 5),
    'source_ip': '203.0.113.50',         # ✅ Populated!
    'destination_ip': '192.168.1.10',    # ✅ Populated!
    'source_port': 52341,
    'destination_port': 22,
    'protocol': 'tcp',
    'action': 'deny',                     # ✅ Populated!
    'log_type': 'authentication',         # ✅ Populated!
    'severity': 'high',
    'vendor': 'fortinet',
    'device_hostname': 'FW-01',
    'message': 'date=2026-02-08 ...',
    'raw_data': {...},
    'business_context': {'is_business_hour': True, ...},
    'created_at': datetime.utcnow()
}

self.batch_clean.append(log_dict)  # Add to batch
```

---

## STEP 4: Batch Accumulation

```python
# Batch state after 1 log:
len(self.batch_clean) = 1
BATCH_SIZE = 100

# Batch not full yet, continue consuming...
```

**As more brute force attempts arrive:**

| Attempt | Time | batch_clean size |
|---------|------|------------------|
| 1 | 14:30:01 | 1 |
| 2 | 14:30:05 | 2 |
| 3 | 14:30:15 | 3 |
| 4 | 14:30:30 | 4 |
| 5 | 14:31:00 | 5 |
| **6** | **14:32:00** | **6** |

---

## STEP 5: Batch Flush & Analysis

### 5.1 Flush Trigger

```python
# Either condition met:
# A) Batch reaches 100 logs, OR
# B) 1-second timeout expires with pending logs

if self._should_flush_batch():
    # Run analysis BEFORE database insert
    all_logs = self.batch_ingest + self.batch_clean
    if all_logs:
        self._run_analysis_on_batch(all_logs)
    
    self._flush_batches()
```

### 5.2 Analysis Pipeline

**File:** `src/services/redis_consumer.py`  
**Function:** `_run_analysis_on_batch()`

```python
for log_dict in logs:
    # Create lightweight proxy object for analyzers
    class LogProxy:
        def __init__(self, d):
            for k, v in d.items():
                setattr(self, k, v)
    
    log_proxy = LogProxy(log_dict)
    
    # Run all registered analyzers
    alerts = analyzer_manager.analyze_log(log_proxy)
    
    if alerts:
        self._store_alerts(alerts)
```

---

## STEP 6: BruteForceAnalyzer Detection

### 6.1 Analyzer Manager Dispatch

**File:** `src/analyzers/base.py`  
**Function:** `AnalyzerManager.analyze_log()`

```python
def analyze_log(self, log) -> List[Alert]:
    alerts = []
    for analyzer in self.analyzers:
        if analyzer.enabled:
            alert = analyzer.analyze(log)
            if alert:
                alerts.append(alert)
    return alerts
```

### 6.2 BruteForceAnalyzer.analyze()

**File:** `src/analyzers/brute_force.py`

**Processing Log #6 (14:32:00):**

```python
def analyze(self, log) -> Optional[Alert]:
    # Step 1: Check if this is an auth failure
    if not self._is_auth_failure(log):
        return None
    
    # _is_auth_failure checks:
    # - log.log_type == "authentication" ✅
    # - log.action == "deny" ✅
    # Result: True - this IS an auth failure
    
    # Step 2: Validate required fields
    source_ip = getattr(log, 'source_ip', None)  # "203.0.113.50" ✅
    tenant_id = getattr(log, 'tenant_id', 'default')  # "central-uni"
    
    if not source_ip:
        return None  # Would skip, but we have source_ip ✅
    
    # Step 3: Update Redis counter
    key = f"bf:central-uni:203.0.113.50"
    count = self.redis_client.incr(key)  # Returns: 6 🚨
    
    # Step 4: Check threshold
    if count >= self.threshold:  # 6 >= 5 ✅ ALERT!
        return self._create_alert(log, count)
    
    return None
```

### 6.3 Redis State During Attack

```
Time: 14:30:01  Key: bf:central-uni:203.0.113.50  Value: 1  TTL: 300s
Time: 14:30:05  Key: bf:central-uni:203.0.113.50  Value: 2  TTL: 295s
Time: 14:30:15  Key: bf:central-uni:203.0.113.50  Value: 3  TTL: 285s
Time: 14:30:30  Key: bf:central-uni:203.0.113.50  Value: 4  TTL: 270s
Time: 14:31:00  Key: bf:central-uni:203.0.113.50  Value: 5  TTL: 240s
Time: 14:32:00  Key: bf:central-uni:203.0.113.50  Value: 6  TTL: 181s 🚨 ALERT!
```

---

## STEP 7: Alert Creation

### 7.1 Alert Object

```python
alert = Alert(
    tenant_id="central-uni",
    alert_type="brute_force",
    severity="high",
    source_ip="203.0.113.50",
    destination_ip="192.168.1.10",
    description=(
        "Brute force attack detected: 6 failed authentication attempts "
        "from 203.0.113.50 in the last 119 seconds"
    ),
    details={
        'attempt_count': 6,
        'threshold': 5,
        'window_seconds': 300,
        'time_remaining': 181,
        'detection_method': 'redis_counter',
        'last_log_type': 'authentication',
        'last_action': 'deny'
    },
    status='open'
)
```

### 7.2 Log Output

```
[WARNING] ALERT: Brute force from 203.0.113.50 (6 attempts in 300s window)
```

---

## STEP 8: Alert Storage

### 8.1 Database Insert

**File:** `src/services/redis_consumer.py`  
**Function:** `_store_alerts()`

```python
def _store_alerts(self, alerts: List[Alert]):
    with db_manager.session_scope() as session:
        for alert in alerts:
            session.add(alert)
        session.commit()
        logger.info(f"Stored {len(alerts)} alerts")
```

### 8.2 PostgreSQL Query

```sql
INSERT INTO alerts (
    tenant_id, alert_type, severity, source_ip, destination_ip,
    description, details, status, created_at
) VALUES (
    'central-uni',
    'brute_force',
    'high',
    '203.0.113.50',
    '192.168.1.10',
    'Brute force attack detected: 6 failed authentication attempts from 203.0.113.50 in the last 119 seconds',
    '{"attempt_count": 6, "threshold": 5, ...}'::jsonb,
    'open',
    '2026-02-08 14:32:00.123456'
)
RETURNING id;

-- Returns: id = 42
```

---

## STEP 9: Batch Database Insert

### 9.1 Log Insert

```python
def _flush_batches(self):
    with db_manager.session_scope() as session:
        all_logs = self.batch_ingest + self.batch_clean
        if all_logs:
            session.bulk_insert_mappings(NormalizedLog, all_logs)
        
        if self.batch_dead:
            session.bulk_insert_mappings(DeadLetter, self.batch_dead)
        
        session.commit()
```

### 9.2 PostgreSQL Query

```sql
INSERT INTO logs (tenant_id, timestamp, source_ip, destination_ip, action, log_type, ...)
VALUES 
  ('central-uni', '2026-02-08 14:30:01', '203.0.113.50', '192.168.1.10', 'deny', 'authentication', ...),
  ('central-uni', '2026-02-08 14:30:05', '203.0.113.50', '192.168.1.10', 'deny', 'authentication', ...),
  ('central-uni', '2026-02-08 14:30:15', '203.0.113.50', '192.168.1.10', 'deny', 'authentication', ...),
  ('central-uni', '2026-02-08 14:30:30', '203.0.113.50', '192.168.1.10', 'deny', 'authentication', ...),
  ('central-uni', '2026-02-08 14:31:00', '203.0.113.50', '192.168.1.10', 'deny', 'authentication', ...),
  ('central-uni', '2026-02-08 14:32:00', '203.0.113.50', '192.168.1.10', 'deny', 'authentication', ...)
RETURNING id;

-- All logs now have populated source_ip, destination_ip, action ✅
```

---

## COMPLETE TIMELINE

| Time | Event | Component | Latency |
|------|-------|-----------|---------|
| 14:30:01.000 | Log #1 pushed to Redis | Repo1 | - |
| 14:30:01.005 | BLPOP returns log #1 | Consumer | 5ms |
| 14:30:01.008 | Schema adapted | LogAdapter | 3ms |
| 14:30:01.009 | Added to batch | Consumer | 1ms |
| 14:30:01.009 | Redis INCR bf:...:203.0.113.50 → 1 | BruteForce | <1ms |
| ... | Logs #2-5 processed | ... | ... |
| 14:32:00.000 | Log #6 pushed to Redis | Repo1 | - |
| 14:32:00.005 | BLPOP returns log #6 | Consumer | 5ms |
| 14:32:00.008 | Schema adapted | LogAdapter | 3ms |
| 14:32:00.009 | Redis INCR → **6** | BruteForce | <1ms |
| 14:32:00.010 | **🚨 ALERT TRIGGERED** | BruteForce | 1ms |
| 14:32:00.015 | Alert stored in DB | PostgreSQL | 5ms |
| 14:32:00.020 | Batch flush started | Consumer | - |
| 14:32:00.120 | 6 logs inserted | PostgreSQL | 100ms |
| **14:32:00.120** | **COMPLETE** | - | **Total: 120ms** |

---

## SYSTEM AT MAXIMUM CAPACITY (1000 logs/sec)

### Observable Metrics

```
# Prometheus metrics
queue_depth_clean: 1000
logs_processed_total: 3,600,000/hour
alerts_generated_total: 1,500/hour
processing_latency_p95: 850ms
processing_latency_p99: 1200ms
worker_count: 1
```

### What You See in Logs

```
[INFO] Batch committed: 100 logs in 95ms
[INFO] Stored 3 alerts
[INFO] Batch committed: 100 logs in 98ms
[WARN] Queue depth high: 1150 (scaling recommended)
[INFO] Batch committed: 100 logs in 92ms
```

### Bottleneck Analysis

| Component | Capacity | Status |
|-----------|----------|--------|
| Redis BLPOP | 50,000 ops/sec | ✅ Comfortable |
| LogAdapter | 10,000 logs/sec | ✅ Comfortable |
| Redis Analyzers | 30,000 ops/sec | ✅ Comfortable |
| PostgreSQL Batch Insert | 1,000 logs/sec | ⚠️ Near limit |
| Alert Deduplication | N/A | ✅ Built-in |

### What Breaks First

1. **Database write throughput** - Need connection pooling or read replicas
2. **Memory pressure** - Batch accumulation during slow flushes
3. **Redis memory** - Old analyzer keys need TTL enforcement

---

## VERIFICATION QUERIES

### Check Logs Are Populated

```sql
SELECT 
    source_ip,
    destination_ip,
    action,
    log_type,
    COUNT(*) 
FROM logs 
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY source_ip, destination_ip, action, log_type
ORDER BY COUNT(*) DESC
LIMIT 10;
```

### Check Alerts Generated

```sql
SELECT 
    alert_type,
    severity,
    source_ip,
    destination_ip,
    description,
    details->>'attempt_count' as attempts,
    created_at
FROM alerts
ORDER BY created_at DESC
LIMIT 10;
```

### Check Redis Counter State

```bash
redis-cli KEYS "bf:*"
redis-cli GET "bf:central-uni:203.0.113.50"
redis-cli TTL "bf:central-uni:203.0.113.50"
```

---

## SUCCESS CRITERIA

Your system is working correctly when:

| Metric | Target | Command to Verify |
|--------|--------|-------------------|
| Logs have populated fields | 100% | `SELECT COUNT(*) FROM logs WHERE source_ip IS NOT NULL` |
| Brute force detected | After 5 fails | `SELECT * FROM alerts WHERE alert_type = 'brute_force'` |
| Port scan detected | After 10 ports | `SELECT * FROM alerts WHERE alert_type = 'port_scan'` |
| Beaconing detected | After 5 callbacks with <0.2 jitter | `SELECT * FROM alerts WHERE alert_type = 'beaconing'` |
| End-to-end latency | <1 second | Check processing_times in consumer metrics |

---

**Document Version**: 1.0  
**Date**: 2026-02-09  
**Author**: Alert Lifecycle Documentation
