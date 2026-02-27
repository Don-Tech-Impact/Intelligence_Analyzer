# File Summary: SIEM API & Services Architecture

## API Layer

### `src/api/__init__.py`
**Purpose:** Package initialization file  
**Status:** Empty (no content)

---

### `src/api/auth.py`
**Purpose:** JWT authentication and authorization for API endpoints  
**Key Functions:**
- `get_public_key()` - Retrieves RS256 public key from config (legacy, not actively used)
- `verify_jwt(token)` - Verifies HS256-signed JWT tokens from Repo1
- `get_current_user(payload)` - Extracts user info from verified JWT payload
- `verify_superadmin(payload)` - Checks for superadmin role/permissions in JWT claims

**Key Details:**
- Uses HS256 (shared secret) for JWT verification, not RS256
- Fails securely if SECRET_KEY not configured
- Handles multiple admin claim locations (root level and nested under `admin` object)
- Extensive logging for debugging secret key mismatches between Repo1 and Repo2
- Auto-error=False on OAuth2 scheme allows graceful handling of missing tokens

**Notable Gaps/TODOs:**
- RS256 support code is present but commented as not actively used
- No refresh token mechanism
- No token revocation beyond logout proxy
- Hardcoded admin keys for debugging ("changeme-admin-key", "fallback-secret-key-for-diagnostic-suffix")

---

### `src/api/health.py`
**Purpose:** Health checks, liveness/readiness probes, and Prometheus metrics  
**Endpoints:**
- `GET /health` - Full health check (database + redis component checks)
- `GET /health/live` - Kubernetes liveness probe
- `GET /health/ready` - Kubernetes readiness probe (checks DB connectivity)
- `GET /metrics` - Prometheus-format metrics with database and queue stats
- `GET /metrics/json` - JSON format metrics

**Metrics Tracked:**
- Application uptime, request counts, error counts
- Log/alert processing counters
- Database table counts (logs, alerts)
- Redis queue sizes (scans for logs:*:ingest, logs:*:clean, logs:*:dead patterns)

**Notable Gaps/TODOs:**
- Metrics are in-memory (reset on restart) - no persistence
- No distributed tracing/span context
- Queue size calculation could be expensive with many tenants
- No alerting thresholds defined

---

### `src/api/main.py`
**Purpose:** FastAPI application entry point with core endpoints and dashboard APIs  
**Key Features:**
- Lifespan management (startup/shutdown hooks)
- Security headers middleware (CSP, X-Frame-Options, etc.)
- CORS configuration (configurable from ALLOWED_ORIGINS env var)
- Rate limiting via slowapi (20/min for alerts, 50/min for logs, etc.)
- Static file serving (Swagger UI, dashboard)

**Endpoints (Public/Admin):**
- `GET /stats` - High-level statistics (logs, alerts, active threats, severity breakdown)
- `GET /alerts` - Recent alerts with filtering by severity
- `GET /logs` - Recent logs with vendor/device/severity/search filters
- `GET /reports` - List generated reports with type/date filtering
- `GET /reports/{report_id}/download` - Download report file
- `POST /reports/generate` - Trigger manual report generation
- `GET /reports/{report_id}/content` - Get HTML report content for in-dashboard viewing
- `GET /analytics/business-insights` - Business hours vs. after-hours breakdown (7-day window)
- `GET /trends` - Activity trends (hourly log/alert counts for last 24h)
- `GET /analytics/top-ips` - Top source/destination IPs
- `GET /analytics/protocols` - Protocol distribution
- `GET /config` - Get SIEM config (thresholds, log level)
- `POST /config` - Update SIEM config and persist to YAML
- `GET /api/dashboard-summary` - Comprehensive dashboard data in single request (combines stats, trends, threats, geo)
- `PATCH /alerts/{alert_id}` - Update alert status and add analyst comments

**Routes Registered:**
- v1_router (JWT protected, tenant-scoped)
- health_router (public)
- admin_router (service-to-service, X-Admin-Key or Superadmin JWT)

**Notable Gaps/TODOs:**
- `to_dict()` helper removes SQLAlchemy state but no proper serialization schema
- Report generation doesn't handle concurrent requests well
- No caching layer for expensive analytics queries
- Dashboard summary recomputes everything on every request
- Analyst comments appended to description field (schema mismatch)
- Error handling generic (500 for all failures)
- No request/response logging at API layer

---

### `src/api/v1_router.py`
**Purpose:** V1 API for frontend dashboard (JWT-protected, tenant-scoped)  
**Dependencies:** `verify_jwt` (requires Bearer token with valid signature)  
**Query Parameter:** `tenant_id` (defaults to "default")

**Endpoints:**

*Dashboard:*
- `GET /api/v1/dashboard/summary` - Comprehensive summary via AnalyticsService

*Logs:*
- `GET /api/v1/logs` - Paginated log listing with severity/vendor/device_type/search filters

*Analytics:*
- `GET /api/v1/analytics/timeline` - Event timeline by range (24h/7d/30d) and bucket (hour/day)
- `GET /api/v1/analytics/threat-vectors` - Top N threat types with counts
- `GET /api/v1/analytics/geo-distribution` - Country breakdown of events
- `GET /api/v1/analytics/traffic` - Network traffic by protocol (byte counts estimated)
- `GET /api/v1/analytics/top-ips` - Top source IPs
- `GET /api/v1/analytics/business-insights` - Business vs. after-hours activity

*Alerts:*
- `GET /api/v1/alerts` - Paginated alerts with severity/status/alert_type filters
- `GET /api/v1/alerts/{alert_id}` - Alert detail with related logs (1-hour window) and contextual recommendations

*Assets:*
- `GET /api/v1/assets` - Discovered assets with pagination
- `GET /api/v1/assets/summary` - Asset inventory summary
- `GET /api/v1/assets/{device_id}` - Detailed asset information

**Helper Functions:**
- `_generate_recommendations(alert_type, severity)` - Returns actionable recommendations based on threat type

**Notable Gaps/TODOs:**
- Many endpoints delegate to service classes (AnalyticsService, AssetService) which are not documented here
- No input validation schemas (Pydantic models)
- Recommendations hardcoded, not data-driven
- No alert export/bulk action endpoints
- No saved search/favorites functionality
- Device type filter uses "device_type" field that may not exist in NormalizedLog (schema mismatch)
- Related logs query hard-coded to 1-hour window (inflexible)

---

### `src/api/admin_router.py`
**Purpose:** Admin API for service-to-service communication with Repo1  
**Authentication:** X-Admin-Key header (shared secret) OR Superadmin Bearer JWT  
**Base URL:** Configurable via REPO1_URL or REPO1_BASE_URL env vars

**Endpoints - Local Analytics (Repo2 Database):**
- `GET /api/admin/tenants/{tenant_id}/usage` - Per-tenant usage stats (logs, alerts, reports, dead letters, estimated storage)
- `GET /api/admin/system/overview` - System-wide stats (tenants, logs, alerts, top 20 tenants by volume)

**Endpoints - Webhook Receiver:**
- `POST /api/admin/tenants/sync` - Idempotent webhook from Repo1 for tenant.created/updated/deleted events

**Endpoints - Auth Proxy (to Repo1):**
- `POST /api/admin/proxy/login` - Proxy login request (no auth required, same as Repo1)
- `POST /api/admin/logout` - Proxy logout with Bearer token forwarding
- `GET /api/admin/auth/jwt-public-config` - Get Repo1's JWT config
- `GET /api/admin/config/verify-sync` - Diagnostic: verify SECRET_KEY alignment with Repo1

**Endpoints - Tenant CRUD Proxy:**
- `GET /api/admin/tenants` - List all tenants with pagination/filtering
- `POST /api/admin/tenants` - Create new tenant
- `GET /api/admin/tenants/{tenant_id}` - Get tenant detail
- `PUT /api/admin/tenants/{tenant_id}` - Update tenant
- `DELETE /api/admin/tenants/{tenant_id}` - Soft-delete tenant

**Endpoints - User CRUD Proxy:**
- `GET /api/admin/users` - List users with pagination
- `POST /api/admin/users` - Create user (password hashed server-side)
- `DELETE /api/admin/users/{username}` - Soft-delete user

**Endpoints - IP Allowlist Proxy:**
- `GET /api/admin/allowlist/{tenant_id}` - Get IP allowlist (flat and rich formats)
- `GET /api/admin/tenants/{tenant_id}/ips` - Get rich IP metadata
- `POST /api/admin/tenants/{tenant_id}/ips` - Add IP/CIDR range
- `DELETE /api/admin/tenants/{tenant_id}/ips/{ip_id}` - Remove IP entry
- `DELETE /api/admin/allowlist/{tenant_id}/{ip:path}` - Legacy route

**Endpoints - API Keys Proxy:**
- `POST /api/admin/tenants/{tenant_id}/api-keys` - Create API key
- `GET /api/admin/tenants/{tenant_id}/api-keys` - List API keys
- `DELETE /api/admin/api-keys/{key_id}` - Revoke API key

**Endpoints - Webhook Configuration Proxy:**
- `POST /api/admin/webhooks/configure` - Set webhook URL override
- `GET /api/admin/webhooks/status` - Get current webhook config
- `DELETE /api/admin/webhooks/configure` - Remove webhook override

**Endpoints - Audit Log Proxy:**
- `GET /api/admin/audit-log` - Retrieve admin audit log from Repo1

**Endpoints - Generic Catch-All:**
- `GET|POST|PUT|DELETE /api/admin/proxy/{path:path}` - Forward any unmapped /admin/* endpoint to Repo1

**Helper Functions:**
- `_get_admin_key()` - Get admin API key (ADMIN_KEY > ADMIN_API_KEY > default)
- `_get_repo1_base()` - Get Repo1 base URL (REPO1_URL > REPO1_BASE_URL > docker default)
- `verify_admin_key()` - Validate X-Admin-Key header
- `verify_admin_or_superadmin()` - Accept either X-Admin-Key OR Superadmin JWT
- `_repo1_request()` - HTTP helper for authenticated requests to Repo1

**Notable Gaps/TODOs:**
- No rate limiting on admin endpoints
- Catch-all proxy could expose sensitive Repo1 endpoints
- Tenant sync webhook doesn't validate Repo1 signature (HMAC)
- Error responses from Repo1 propagated directly (leaks implementation details)
- No caching for frequently accessed data (allowlist, config)
- Estimated storage calculation (500 bytes/log) is hardcoded guess
- No bulk operations (e.g., delete multiple tenants)
- Logout doesn't invalidate Repo2 session state
- No audit logging of admin actions on Repo2 side

---

## Service Layer

### `src/services/log_adapter.py`
**Purpose:** Normalize logs from multiple Repo1 formats to standardized NormalizedLogSchema  
**Key Method:** `LogAdapter.normalize(raw_log)` - Auto-detects format and converts

**Supported Formats:**
1. **V1 Schema** (raw ingest from logs:{TENANT}:ingest)
   - Has `schema_version: "v1"`
   - Raw syslog in `raw_log` field
   - Metadata in `metadata` object (device_type, source_ip, tenant_id)

2. **v2.0 Schema** (parsed/structured from logs:{TENANT}:clean)
   - Has `schema_version: "v2.0" | "v2.1"` etc.
   - Nested structure: `source`, `destination`, `event`, `network`, `device`, `threat_intel`, `business_context`, `raw`
   - Full field extraction (IPs, ports, protocols, actions, severity)

3. **Legacy 'normalized' Wrapper**
   - Fields nested under `normalized` key
   - Detects v2.0 or assumes flat format

4. **Legacy 'parsed/metadata' Wrapper**
   - Fields in `parsed` object (src_ip, dst_ip, src_port, dst_port, action)
   - Metadata in `metadata` object

5. **Flat Format**
   - Direct fields at root level (source_ip, destination_ip, action, etc.)

**Detection Order:**
1. Check for v1 schema
2. Check for v2.x schema
3. Check for 'normalized' wrapper
4. Check for 'parsed' wrapper
5. Check for nested structure (SIF format)
6. Default to flat format

**Output Fields (NormalizedLogSchema):**
- `tenant_id`, `company_id`, `device_id`
- `timestamp` - parsed from multiple formats
- `source_ip`, `destination_ip`, `source_port`, `destination_port`
- `protocol`, `action`, `log_type`, `severity`
- `vendor`, `device_hostname`, `message`
- `raw_data` (original input), `business_context`

**Helper Functions:**
- `_map_device_type_to_vendor()` - Maps cisco_asa → cisco, etc.
- `_parse_timestamp()` - Handles ISO8601, Unix epoch, custom formats
- `_safe_int()` - Safely convert port numbers
- `_create_error_log()` - Create fallback log on normalization failure

**Notable Gaps/TODOs:**
- No schema validation (accepts any dict structure)
- Error handling creates low-severity error logs instead of raising exceptions
- V1 schema parsing doesn't extract network fields from raw syslog (only stores raw message)
- No support for custom field mapping
- Device_type to vendor mapping is hardcoded and incomplete
- Timestamp parsing tries multiple formats in sequence (inefficient)
- No handling of array fields (tags, multiple IPs, etc.)
- Missing documentation on expected output when fields are missing

---

### `src/services/log_ingestion.py`
**Purpose:** Main analysis pipeline: normalize → store → enrich → analyze → notify  
**Key Class:** `AnalysisPipeline`

**Pipeline Flow:**
1. **Normalize** - Use LogAdapter to validate/standardize log
2. **Store** - Insert NormalizedLog to database with expire_on_commit=False
3. **Enrich** - Call EnrichmentService (GeoIP, Threat Intel, Scoring)
4. **Analyze** - Run analyzer_manager against enriched log
5. **Alert** - Pass generated alerts to notification_manager

**Methods:**
- `process_log(raw_log_data)` - Main entry point, returns True/False
- `_store_log(schema)` - Insert to DB, handle session lifecycle
- `_handle_alerts(alerts)` - Iterate alerts and call notification_manager

**Database Details:**
- Uses `db_manager.session_scope()` context manager
- Sets `expire_on_commit=False` to keep attributes accessible after commit
- Catches exceptions and rolls back on store failure

**Notable Gaps/TODOs:**
- No batching (processes one log at a time)
- `process_log` always returns True/False but doesn't retry on DB errors
- No deduplication of logs (same raw_log could be processed twice)
- Error logging is generic ("Error in analysis pipeline: {e}")
- No metrics/counters for success/failure rates
- Analyzer registration happens via `import src.analyzers` side effect (implicit)
- EnrichmentService is imported but usage not well integrated (no error handling)
- Dead letter queue not used (exceptions silently logged)
- No async support (blocking on all operations)

---

### `src/services/webhook_alert.py`
**Purpose:** Send alert notifications to Discord and/or Slack webhooks  
**Key Class:** `WebhookAlertService`

**Methods:**
- `__init__()` - Load webhook URLs and enabled flag from config
- `send_alert(alert: Alert)` - Format and dispatch to configured webhooks
- `_send_to_discord(message)` - POST to Discord with {"content": message}
- `_send_to_slack(message)` - POST to Slack with {"text": message}

**Configuration:**
- `webhooks_enabled` - Feature flag
- `discord_webhook_url` - Optional Discord webhook URL
- `slack_webhook_url` - Optional Slack webhook URL

**Alert Message Format:**
```
🚨 **SIEM ALERT: {alert_type}**
**Severity**: {SEVERITY}
**Source IP**: {source_ip}
**Description**: {description}
**Tenant**: {tenant_id}
```

**Error Handling:**
- Exceptions logged but not raised (fail-silent)
- 5-second timeout per request
- No retry logic

**Notable Gaps/TODOs:**
- No support for additional webhooks (Teams, PagerDuty, etc.)
- Message format is hardcoded (no customization)
- No message batching (one HTTP call per alert)
- No request signing/verification (HMAC)
- No delivery confirmation/acknowledgment
- No rate limiting (could spam webhooks)
- Discord embeds not used (could be richer)
- No alert deduplication before sending
- No support for alert severity thresholds (sends all alerts)

---

### `src/services/redis_consumer.py`
**Purpose:** Consume logs from Redis queues, batch process, and pipeline to DB  
**Key Class:** `RedisConsumer`

**Architecture:**
- **Dynamic Queue Discovery** - Scans for logs:{TENANT}:ingest/clean/dead patterns every 30s
- **Batch Processing** - Accumulates logs up to BATCH_SIZE (100) or BATCH_TIMEOUT_MS (1s)
- **Fast Insert** - Uses `bulk_insert_mappings()` for 50x speedup vs. individual inserts
- **Multi-Tenant** - One consumer instance monitors all tenant queues
- **Error Handling** - Individual errors logged, batch failures retried 3x then moved to dead_letters

**Configuration:**
- `BATCH_SIZE` - Default 100 logs per batch
- `BATCH_TIMEOUT_MS` - Default 1000ms flush interval
- `redis_queue_scan_interval` - Default 30s between queue discovery scans

**Queue Types:**
- `logs:{TENANT}:ingest` - Raw logs (full pipeline: normalize → enrich → analyze)
- `logs:{TENANT}:clean` - Pre-normalized logs (fast path: enrich → analyze)
- `logs:{TENANT}:dead` - Failed logs (store-only for audit)

**Key Methods:**

*Initialization & Connection:*
- `__init__()` - Initialize with empty batches, metrics, DB
- `connect()` - Establish Redis connection with health check
- `disconnect()` - Close Redis connection

*Queue Discovery:*
- `_discover_tenant_queues()` - Scan Redis for new/removed tenants
- `_should_rescan()` - Check if rescan interval elapsed

*Log Processing:*
- `_handle_ingest_log(log_data)` - Normalize raw log and batch for pipeline
- `_handle_clean_log(log_data)` - Fast-path pre-normalized logs
- `_handle_dead_log(log_data)` - Store in dead_letters + attempt recovery/analysis

*Batch Management:*
- `_should_flush_batch()` - Check if size or timeout threshold reached
- `_flush_batches()` - Bulk insert all pending logs/dead letters to DB
- `_run_analysis_on_batch(logs)` - Run analyzer_manager on batch + severity adjustments
- `_store_alerts(alerts)` - Persist generated alerts to DB

*Metrics & Monitoring:*
- `get_queue_sizes()` - Get size of each discovered queue
- `get_total_queue_size()` - Sum of all queue sizes
- `_log_final_metrics()` - Print summary on shutdown

**Main Loop (`start()`):**
```
1. Connect to Redis
2. Discover tenant queues
3. Loop:
   - If rescan interval elapsed: rediscover queues
   - BLPOP (blocking) from all queues with 1s timeout
   - Process message (route by queue type)
   - If batch should flush: run analysis → bulk insert → commit
   - Handle Redis errors (retry up to 10 consecutive)
4. On shutdown: flush remaining batch
```

**Dead Log Recovery Feature:**
- Stores raw payload in dead_letters table (audit trail)
- Attempts to parse `raw_log` field and normalize for analysis
- Sets confidence=0.3 on recovered logs (lower weight in detection)
- Downgrades alert severity if confidence < 0.5 (avoid false positives)

**Confidence-Weighted Analysis:**
- Dead-recovered logs (confidence < 0.5): severity critical→medium, high→low
- Business-hours severity boost: off-hours/weekend events upgraded (low→medium, medium→high)

**Notable Gaps/TODOs:**
- No DLQ for failed batch commits (just logs error)
- Queue discovery happens in main loop (blocks briefly during scan)
- No explicit connection pooling (one connection per consumer)
- Batch timeout is wall-clock, not message-based (could delay if queue is empty)
- Analysis runs on full batch (no incremental analysis)
- Dead log recovery only attempts if raw_log is present (many logs won't recover)
- Metrics are in-memory (lost on restart)
- No circuit breaker for repeated Redis errors
- BLPOP timeout=1s is hardcoded (not configurable)
- No graceful shutdown timeout (waits indefinitely for batch flush)
- No support for consumer groups (single consumer = single instance bottleneck)
- Log adapter errors during batch processing move to dead letters (not retried)
- Alert deduplication not handled (analyzer_manager expected to do it)
- No support for priority queue (all queues polled equally)

---

## Summary Table

| Component | Responsibility | Auth | Notable Limitations |
|-----------|-----------------|------|----------------------|
| `auth.py` | JWT verification (HS256) | Token validation | No refresh tokens, hardcoded debug keys |
| `health.py` | Service health & Prometheus metrics | Public | In-memory metrics, no persistence |
| `main.py` | Core dashboard APIs & stats | Admin key or JWT | No caching, no request logging |
| `v1_router.py` | Frontend API (tenant-scoped) | JWT | Hardcoded recommendations, schema mismatches |
| `admin_router.py` | Service-to-service proxy | X-Admin-Key or JWT | No signature verification, leaks Repo1 errors |
| `log_adapter.py` | Multi-format log normalization | N/A | No schema validation, V1 doesn't extract fields |
| `log_ingestion.py` | Analysis pipeline orchestration | N/A | No batching, no retry logic, no DLQ |
| `webhook_alert.py` | Discord/Slack notifications | N/A | Hardcoded format, no rate limiting |
| `redis_consumer.py` | Batch log ingestion from Redis | N/A | No DLQ for batches, single-instance bottleneck |

---

## Cross-Cutting Concerns

**Authentication:**
- V1 API and Admin APIs use different auth mechanisms (JWT vs X-Admin-Key)
- No unified token refresh or session management
- Debug keys hardcoded in config

**Data Quality:**
- Log adapter doesn't validate fields (garbage in, garbage out)
- Dead logs recovered with low confidence (0.3) but could contain valid intelligence
- No deduplication across pipeline

**Error Handling:**
- Mostly fail-silent with logging (exceptions swallowed)
- No structured error codes or standardized error responses
- Dead letter queues not fully leveraged

**Scalability Issues:**
- Single Redis consumer instance (no consumer groups/sharding)
- Dashboard summary recomputes everything on each request
- No caching layer for expensive queries
- Webhook alerts sent sequentially (could parallelize)

**Observability Gaps:**
- Metrics are in-memory (lost on restart)
- No distributed tracing or request IDs
- Limited structured logging
- No alerting on pipeline health
