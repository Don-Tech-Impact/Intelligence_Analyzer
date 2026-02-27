# System State Report — Afric Analyzer (Repo 2)
## Current State, What Is Working & Technical Details

> **Generated:** 2026-02-26  
> **Test results:** 146/146 passing ✅  
> **Repo 1:** Running on Docker at `http://localhost:8080`  
> **Repo 2:** Analytics / SIEM Consumer (this repo)

---

## 1. Test Suite Health

| Test File | Tests | Status | Notes |
|---|---|---|---|
| `test_admin_api.py` | 13 | ✅ All pass | Admin auth, system overview, tenant usage |
| `test_api.py` | 5 | ✅ All pass | Core API health, stats, dashboard |
| `test_analyzers.py` | 10 | ✅ All pass | BruteForce, PortScan, Beaconing, Payload |
| `test_legacy_hardening.py` | 18 | ✅ All pass | Legacy endpoint auth protection |
| `test_log_adapter.py` | varies | ✅ All pass | Log normalization (all vendors) |
| `test_normalization.py` | varies | ✅ All pass | Schema normalization |
| `test_redis_integration.py` | varies | ✅ All pass | Redis consumer logic |
| `test_reporting.py` | varies | ✅ All pass | Report generation |
| `test_reporting_ai.py` | 5 | ✅ All pass | Reporting + AI endpoints (was failing) |
| `test_services.py` | varies | ✅ All pass | Service layer pipeline |
| `test_tenant_isolation.py` | 4 | ✅ All pass | Multi-tenant data isolation (was failing) |
| `test_v1_api.py` | 21 | ✅ All pass | V1 API all endpoints (was failing) |
| `repo2-rovo/test_integration.py` | 37 | ✅ All pass | Repo 1 ↔ Repo 2 contract tests |
| **TOTAL** | **146** | **✅ 146/146** | **Zero failures** |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    REPO 1 (:8080)                    │
│           Log Ingestion API (Docker)                 │
│                                                      │
│  POST /admin/login          → JWT tokens             │
│  POST /admin/tenants        → tenant lifecycle       │
│  POST /api/logs/ingest      → raw log ingestion      │
│  POST /api/logs/batch       → batch log ingestion    │
│  POST /admin/webhooks/configure → webhook URL setup  │
│  GET  /metrics              → Prometheus metrics     │
└──────────────┬─────────────────────────┬────────────┘
               │ LPUSH                   │ POST webhook
               ▼                         ▼
┌─────────────────────┐    ┌─────────────────────────┐
│   Redis (shared)    │    │  POST /api/admin/        │
│                     │    │  tenants/sync            │
│ logs:{t}:ingest     │    │  (Repo 2 receives)       │
│ logs:{t}:clean  ◄───┼────┤                         │
│ logs:{t}:dead       │    └─────────────────────────┘
└──────────┬──────────┘
           │ BRPOP (FIFO)
           ▼
┌─────────────────────────────────────────────────────┐
│                    REPO 2 (:8000)                    │
│           Analytics / SIEM Consumer                  │
│                                                      │
│  RedisConsumer   → reads :clean, :ingest, :dead      │
│  AnalysisPipeline → normalize → enrich → analyze     │
│  Threat Analyzers → BruteForce, PortScan, Beaconing  │
│  AlertManager    → email + Discord/Slack webhooks    │
│                                                      │
│  GET  /api/v1/dashboard/summary   (JWT protected)   │
│  GET  /api/v1/analytics/*         (JWT protected)   │
│  GET  /api/v1/alerts              (JWT protected)   │
│  GET  /api/v1/assets              (JWT protected)   │
│  GET  /api/admin/system/overview  (X-Admin-Key)     │
│  GET  /api/admin/tenants/{id}/usage (X-Admin-Key)   │
│  POST /api/admin/tenants/sync     (X-Admin-Key)     │
│  GET  /health                     (no auth)         │
│  GET  /metrics                    (no auth)         │
└─────────────────────────────────────────────────────┘
```

---

## 3. What Is Fully Working

### 3.1 Redis Consumer (FIFO Queue Processing)
**File:** `src/services/redis_consumer.py`

- **Fixed:** `BLPOP` → `BRPOP` — now reads FIFO (oldest log first) per Repo 1 contract
- Dynamically discovers all `logs:{tenant_id}:ingest/clean/dead` queues via `scan_iter`
- Re-scans every 30 seconds to pick up new tenants automatically
- Batch processing: accumulates 100 logs OR waits 1 second, then bulk-inserts
- Queue routing:
  - `:ingest` → full pipeline (normalize → enrich → analyze → alert)
  - `:clean` → fast path (already parsed by Repo 1 worker)
  - `:dead` → stored in `DeadLetter` table + attempted intelligence recovery at confidence 0.3
- Metrics tracked: logs processed, failures, batch sizes, tenants discovered

### 3.2 Webhook Receiver
**File:** `src/api/admin_router.py` → `POST /api/admin/tenants/sync`

- **Fixed:** Returns HTTP **401** (not 422) when `X-Admin-Key` is missing or wrong
- Handles all three event types: `tenant.created`, `tenant.updated`, `tenant.deleted`
- Upserts into local `Tenant` table (idempotent — safe to receive duplicates)
- Soft-deletes on `tenant.deleted` (sets `is_active = False`, data preserved)

### 3.3 V1 API (Frontend / Dashboard)
**File:** `src/api/v1_router.py` — prefix `/api/v1`

All endpoints JWT-protected (HS256, `SECRET_KEY` shared with Repo 1):

| Endpoint | Description |
|---|---|
| `GET /api/v1/dashboard/summary` | Total events, active threats, risk score, affected assets |
| `GET /api/v1/logs` | Paginated logs with filters (severity, vendor, device, search) |
| `GET /api/v1/analytics/timeline` | Event/threat timeline (24h/7d/30d, hour/day buckets) |
| `GET /api/v1/analytics/threat-vectors` | Top N threat types with counts and trends |
| `GET /api/v1/analytics/geo-distribution` | Country breakdown with event/threat counts |
| `GET /api/v1/analytics/traffic` | Protocol breakdown with byte estimates |
| `GET /api/v1/analytics/top-ips` | Top source IPs by event count |
| `GET /api/v1/analytics/business-insights` | Business hours vs after-hours activity |
| `GET /api/v1/alerts` | Paginated alerts with severity/status/type filters |
| `GET /api/v1/alerts/{id}` | Alert detail with related logs and recommendations |
| `GET /api/v1/assets` | Discovered devices with pagination and search |
| `GET /api/v1/assets/summary` | Asset inventory: totals by type, assets with threats |
| `GET /api/v1/assets/{device_id}` | Device detail: vendor, severity distribution, recent alerts |

### 3.4 Admin API (Service-to-Service)
**File:** `src/api/admin_router.py` — prefix `/api/admin`

Auth: `X-Admin-Key` header OR `Bearer JWT` (superadmin).

**Local analytics (Repo 2 DB):**
- `GET /api/admin/system/overview` — cross-tenant stats: totals, top 20 tenants by volume
- `GET /api/admin/tenants/{tenant_id}/usage` — per-tenant logs/alerts/reports/dead-letters/storage

**Proxy to Repo 1 (all CRUD operations):**
- Tenant CRUD: create, list (with correct `limit` param), get, update, delete
- API Key management: create, list, revoke
- IP Allowlist: add, list, remove
- User management: create, list, delete
- Webhook configuration: set, get, delete override
- Audit log retrieval
- Login/logout proxy (CORS bypass for frontend)
- Catch-all proxy: `/api/admin/proxy/{path:path}`

### 3.5 Threat Detection Analyzers
**Files:** `src/analyzers/`

| Analyzer | What it detects | Trigger |
|---|---|---|
| `BruteForceAnalyzer` | ≥5 failed logins from same IP in 5 min | Per log |
| `PortScanAnalyzer` | ≥10 unique destination ports from same IP | Per log |
| `BeaconingAnalyzer` | Regular C2 beacon intervals (±10% jitter) | Batch |
| `ThreatIntelAnalyzer` | IP/domain matches known threat indicators | Per log |
| `PayloadAnalysisAnalyzer` | SQL injection, XSS, shell injection patterns | Per log |

### 3.6 Log Normalization (Multi-Vendor)
**File:** `src/services/log_adapter.py`

Accepts all Repo 1 log envelope formats and normalizes to `NormalizedLogSchema`:

| Vendor | Detection | Example |
|---|---|---|
| Cisco ASA | `%ASA-` prefix | `%ASA-4-106023: Deny tcp ...` |
| Fortinet | `devname=` + `srcip=` + `dstip=` | `devname="FG100E" srcip=1.2.3.4 ...` |
| pfSense | `pfSense filterlog:` | `<134>... filterlog: 1,16777216,...` |
| Ubiquiti | `kernel:` + `IN=` + `OUT=` | `kernel: [WAN_LOCAL]IN=eth0 ...` |
| OpenWRT | Router syslog pattern | `daemon.info dnsmasq: query[A] ...` |
| Windows | Security event pattern | `Microsoft-Windows-Security/4624 ...` |
| Unknown | Confidence < 0.5 | → dead letter queue |

Schema versions supported: `v1` (raw), `v2.x` (parsed), `normalized`, `parsed/metadata`, flat.

### 3.7 Enrichment Pipeline
**File:** `src/services/enrichment.py`

Each log is enriched with:
- **Threat Intelligence:** Source/dest IP checked against `ThreatIntelligence` table
- **GeoIP:** Country/region assigned from IP prefix (mocked — replace with MaxMind)
- **Threat Score:** 0–100 calculated from severity + intel matches + business hours context
- **Business Hours Context:** Off-hours/weekend activity boosts threat score

### 3.8 Alerting & Notifications
**Files:** `src/services/email_alert.py`, `src/services/webhook_alert.py`, `src/services/notification_manager.py`

- Email alerts via SMTP (TLS/AUTH) for high/critical severity
- Discord + Slack webhook notifications
- Batch email sending every 5 minutes (scheduler-driven)
- Alert deduplication: source IP + alert type + 1-hour window

### 3.9 Report Generation
**File:** `src/services/report_generator.py`

- Daily / weekly / monthly / custom date range reports
- HTML output: professional executive summary with metrics, tables, risk distribution
- CSV output: structured data export
- Stored in `Report` table with file paths
- Scheduled daily generation via APScheduler

### 3.10 Health & Metrics
**File:** `src/api/health.py`

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | None | DB + Redis component health |
| `GET /health/live` | None | Kubernetes liveness (`{"status":"alive"}`) |
| `GET /health/ready` | None | Kubernetes readiness |
| `GET /metrics` | None | Prometheus text format |
| `GET /metrics/json` | None | JSON metrics |

Prometheus metrics tracked:
- `siem_logs_processed_total`
- `siem_alerts_created_total`
- `siem_api_requests_total`
- `siem_errors_total`
- `siem_uptime_seconds`
- `siem_queue_size`

---

## 4. Startup Webhook Registration

**File:** `src/main.py` → `_register_webhook_with_repo1()`

On every startup, Repo 2 now automatically:
1. Reads `REPO2_WEBHOOK_URL` from environment
2. POSTs to `REPO1_BASE_URL/admin/webhooks/configure`
3. Repo 1 stores the URL in Redis and uses it for all future tenant events
4. Non-blocking: failure logs a warning but never crashes startup

**Manual registration:**
```bash
python repo2-rovo/startup_webhook_register.py
```

---

## 5. Authentication Architecture

### 5.1 JWT (V1 API — Frontend)
- Algorithm: **HS256**
- Secret: `SECRET_KEY` env var — **must match Repo 1 exactly**
- Token lifetime: 3600 seconds (issued by Repo 1)
- Refresh: call `POST /api/admin/proxy/login` from Repo 2 to get fresh token
- Verify endpoint: `GET /api/admin/config/verify-sync` (no secret over wire)

### 5.2 X-Admin-Key (Admin API + Webhook)
- Secret: `ADMIN_KEY` env var (alias: `ADMIN_API_KEY`) — **must match Repo 1**
- Used for: webhook receiver, system overview, tenant usage, all Repo 1 proxies
- **Fixed:** missing key → HTTP **401** (was 422)
- **Fixed:** wrong key → HTTP **401** (was 403 on some endpoints)

### 5.3 X-API-Key (Log Ingestion — Repo 1 side only)
- Used by log forwarders to POST to Repo 1's `/api/logs/ingest`
- Repo 2 creates these keys via `POST /api/admin/tenants/{id}/api-keys`
- Full key shown only once at creation — store immediately

---

## 6. Database Schema

**Engine:** SQLite (dev) / PostgreSQL (prod)  
**ORM:** SQLAlchemy with session-scoped multi-tenancy

| Table | Purpose |
|---|---|
| `normalized_logs` | All processed security logs (tenant-scoped) |
| `alerts` | Detected threats (tenant-scoped) |
| `tenants` | Local tenant registry (synced via webhook) |
| `threat_intelligence` | Known malicious IPs/domains/hashes |
| `reports` | Report metadata + file paths |
| `dead_letters` | Failed/unparseable logs with error context |
| `audit_logs` | Local admin action audit trail |

**Tenant isolation:** every query filters on `tenant_id` — verified by `test_tenant_isolation.py`.

---

## 7. Redis Key Layout

```
# Log queues (Repo 1 writes, Repo 2 reads via BRPOP)
logs:{tenant_id}:ingest    # Raw ingest envelopes
logs:{tenant_id}:clean     # Parsed/normalized logs (primary consumer queue)
logs:{tenant_id}:dead      # Failed/unparseable logs

# Rate limiting (Repo 1 manages)
ratelimit:{key_id}:{endpoint}
burst:{key_id}:{endpoint}

# Webhook config (shared)
webhook:url

# JWT blocklist (Repo 1 manages)
admin:token:blocklist:{token_hash}

# Tenant metadata (Repo 1 manages)
tenant:{tenant_id}
tenant:index
```

---

## 8. Environment Variables (Required)

```env
# Shared with Repo 1 — MUST match exactly
SECRET_KEY=<same-as-repo1>          # JWT signing secret (HS256)
ADMIN_KEY=<same-as-repo1>           # Webhook + admin API auth
ADMIN_API_KEY=<same-as-repo1>       # Alias for backward compat

# Repo 1 connection
REPO1_BASE_URL=http://localhost:8080 # or http://repo1_api:8080 in Docker
REPO1_URL=http://localhost:8080      # Alias

# Redis (shared with Repo 1)
REDIS_URL=redis://localhost:6379/0

# Webhook (Repo 2 self-URL — registered with Repo 1 on startup)
REPO2_WEBHOOK_URL=http://repo2-host:8000/api/admin/tenants/sync

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/siem_db

# Optional
DEAD_LETTER_ALERT_THRESHOLD=100     # Alert when DLQ exceeds this
BATCH_SIZE=100                       # Logs per Redis batch
BATCH_TIMEOUT_MS=1000               # Max wait before flushing batch
```

---

## 9. Files Changed in This Session

| File | Change | Reason |
|---|---|---|
| `src/api/admin_router.py` | `verify_admin_key`: `Header(...)` → `Header(None)` | 422 → 401 for missing key |
| `src/services/redis_consumer.py` | `blpop` → `brpop` | LIFO → FIFO queue order |
| `src/main.py` | Added `_register_webhook_with_repo1()` + startup call | Auto webhook registration |
| `tests/test_v1_api.py` | Added `app.dependency_overrides[verify_jwt]` | Mock JWT for tests |
| `tests/test_tenant_isolation.py` | Added `app.dependency_overrides[verify_jwt]` | Mock JWT for tests |
| `tests/test_legacy_hardening.py` | Force `ADMIN_KEY` env var before import | Key resolution fix |
| `tests/test_reporting_ai.py` | Force `ADMIN_KEY` + fix 422/403 → 401 assertions | Match fixed behavior |
| `tests/test_admin_api.py` | Force `ADMIN_KEY` + fix 422/403 → 401 assertions | Match fixed behavior |
| `repo2-rovo/INTEGRATION.md` | Full integration assessment | New |
| `repo2-rovo/webhook_receiver_fix.py` | Complete fix + patch instructions | New |
| `repo2-rovo/redis_queue_adapter.py` | BRPOP consumer + queue helpers | New |
| `repo2-rovo/admin_client.py` | Typed Repo 1 client (correct params) | New |
| `repo2-rovo/startup_webhook_register.py` | Auto webhook registration script | New |
| `repo2-rovo/docker-compose.repo2.yml` | Docker network overlay | New |
| `repo2-rovo/test_integration.py` | 37 contract tests | New |
| `repo2-rovo/SYSTEM_STATE.md` | This document | New |

---

## 10. Known Limitations & Next Steps

| Item | Status | Notes |
|---|---|---|
| GeoIP resolution | Mock only | Replace with MaxMind GeoLite2 or ip-api.com |
| Alert deduplication | Basic (IP + type + 1h window) | No cross-log grouping/clustering |
| Report file cleanup | No archival policy | Old HTML/CSV files accumulate on disk |
| JWT token refresh | Manual | Repo 2 frontend must re-login every 55 min |
| Dead letter retry | One-shot only | No exponential backoff retry queue |
| Webhook retry | None (by Repo 1 design) | Repo 2 must handle idempotency |
| Threat intel feeds | Mock URLs | Replace with real OSINT/commercial feeds |
| RBAC | Superadmin only | No granular per-tenant role model |
| Rate limiting | Basic SlowAPI | Not per-tenant, not Redis-backed |
| `REPO2_URL` on Repo 1 side | Must be set manually | Alternative to webhook registration |
