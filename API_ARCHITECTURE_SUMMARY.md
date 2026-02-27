# API Architecture Summary

## Overview
This is a FastAPI-based SIEM (Security Information and Event Management) analyzer system with multi-tenant support. The application consists of three main API routers (V1, Admin, and Health) protected by different authentication mechanisms. The system processes logs, generates alerts, and provides analytics/reporting capabilities.

---

## File-by-File Analysis

### 1. `src/api/auth.py` - JWT Authentication & Authorization

**Purpose:** Central authentication module handling JWT verification and role-based access control.

**Key Functions:**

| Function | Purpose | Auth Mechanism |
|----------|---------|-----------------|
| `get_public_key()` | Retrieves RS256 public key from config (legacy, not currently used) | N/A |
| `verify_jwt(token)` | Dependency that verifies JWT tokens using HS256 with a shared SECRET_KEY | JWT (HS256) |
| `get_current_user(payload)` | Extracts and returns user info from verified JWT payload | Depends on `verify_jwt` |
| `verify_superadmin(payload)` | Validates superadmin privileges from JWT claims | Depends on `verify_jwt` |

**Auth Mechanism Details:**

- **Algorithm:** HS256 (HMAC with SHA-256) using shared `SECRET_KEY`
- **Token Source:** OAuth2PasswordBearer from `/dashboard/login` endpoint
- **Key Configuration:** 
  - Primary: `config.secret_key` (from environment/config)
  - Fallback: Hardcoded `"fallback-secret-key-for-diagnostic-suffix"` (diagnostic only)
  - Default Admin Key: `"changeme-admin-key"` (development/testing)
  
- **Superadmin Detection Logic:** Checks multiple claim fields:
  - `role == "superadmin"` (case-insensitive)
  - `is_admin == True`
  - `username == "superadmin"` (case-insensitive)
  - `email` contains `"admin@"` (case-insensitive)
  - Also checks nested `admin` object in payload (compatibility with Repo 1)

**Error Handling:**
- HTTP 401: No token or token expired
- HTTP 403: Insufficient permissions for superadmin operations
- HTTP 500: Missing SECRET_KEY configuration

**Middleware/Dependencies:**
- `oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/dashboard/login", auto_error=False)`
- Uses `python-jose` library for JWT operations

**TODOs/Missing Pieces:**
```python
# Line 40: Comment indicates RS256 public key is for backward compatibility
# but is no longer used—all verification is now HS256
public_key = get_public_key() # We keep this for backward compatibility if needed, but primary is now HS256

# Lines 46, 55: References "changeme-admin-key" and diagnostic logging suggest
# this file expects migration to a more robust secret management system
```

**Security Notes:**
- Fail-secure approach: If no SECRET_KEY is configured, access is denied
- Extensive logging of key metadata (length, suffix) for diagnostics
- Warning if fallback secret is used (indicates .env not loaded)
- Unverified payload details returned in error messages (may expose claims structure)

---

### 2. `src/api/main.py` - FastAPI Application & Root Endpoints

**Purpose:** Main FastAPI application setup with root-level endpoints for stats, alerts, logs, reports, and analytics.

**Application Configuration:**
- **Title:** Intelligence Analyzer API
- **Version:** 1.0.0
- **Docs URL:** `/docs` (custom HTML with local Swagger UI assets)
- **OpenAPI:** `/openapi.json`
- **Lifespan Handler:** Manages database initialization on startup

**Routes & Endpoints:**

| Endpoint | Method | Auth | Rate Limit | Purpose |
|----------|--------|------|-----------|---------|
| `/stats` | GET | `verify_admin_key` | None | High-level statistics by tenant |
| `/alerts` | GET | `verify_admin_key` | 20/min | Get recent alerts with filtering |
| `/logs` | GET | `verify_admin_key` | 50/min | Get logs with vendor/device/severity filters |
| `/reports` | GET | `verify_admin_key` | 5/min | List generated reports |
| `/reports/{report_id}/download` | GET | `verify_admin_key` | None | Download report file |
| `/reports/{report_id}/content` | GET | `verify_admin_key` | None | Get HTML content of report |
| `/reports/generate` | POST | `verify_admin_key` | 2/min | Trigger manual report generation |
| `/analytics/business-insights` | GET | `verify_admin_key` | None | Business hours vs after-hours analysis |
| `/analytics/top-ips` | GET | `verify_admin_key` | None | Top source/destination IPs |
| `/analytics/protocols` | GET | `verify_admin_key` | None | Protocol distribution |
| `/trends` | GET | `verify_admin_key` | None | Activity trends (last 24h) |
| `/config` | GET | `verify_admin_key` | None | Get SIEM configuration |
| `/config` | POST | `verify_admin_key` | None | Update SIEM configuration |
| `/api/dashboard-summary` | GET | `verify_admin_key` | 10/min | Comprehensive dashboard data |
| `/alerts/{alert_id}` | PATCH | None | None | Update alert status & comments |
| `/docs` | GET | None | None | Custom Swagger UI |
| `/redoc` | GET | None | None | ReDoc documentation |
| `/openapi.json` | GET | None | None | OpenAPI schema |
| `/static/*` | GET | None | None | Static files (Swagger, assets) |
| `/dashboard/*` | GET | None | None | Dashboard application files |

**Auth Mechanism:**
- **Primary:** `verify_admin_key` (X-Admin-Key header)
- **Secondary:** `verify_superadmin` (JWT from `/api/v1` routes, not used on root endpoints)

**Middleware Present:**

1. **CORS Middleware:**
   - Origins: From `ALLOWED_ORIGINS` env var (default: `http://localhost:3000,http://localhost:8000`)
   - Allows: All methods, All headers, Credentials enabled

2. **Rate Limiting (SlowAPI):**
   - `limiter = Limiter(key_func=get_remote_address)`
   - Applied to specific endpoints (20/min, 50/min, 5/min, 2/min, 10/min)
   - Handler: `_rate_limit_exceeded_handler`

3. **Security Headers Middleware:**
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `X-XSS-Protection: 1; mode=block`
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `Content-Security-Policy`: Allows CDN resources for Swagger UI

4. **Global Exception Handler:**
   - Catches unhandled exceptions and returns HTTP 500
   - Logs full traceback
   - Returns error message (or generic message if not in debug mode)

**Static File Mounts:**
- `/static/swagger-ui/` → Swagger UI assets
- `/static/` → General static files and HTML
- `/dashboard/` → Dashboard React application

**Database:**
- Dependency injection via `get_db()` yields session from `db_manager`
- Session closes in finally block

**TODOs/Missing Pieces:**
```python
# Line 181: Comment indicates authentication was removed
# "Authentication removed — managed by Repo 1 (Afric Analyzer)."
# This suggests auth responsibility is delegated to another service

# Line 539: get_alerts() called without passing required request parameter
# potential bug when called from get_dashboard_summary()

# Lines 545-546, 549-552: Uses json_extract() which is SQLite-specific
# May not work with PostgreSQL or MySQL without adaptation
```

**Security Notes:**
- Admin key endpoints don't validate tenant ownership—relying on key security
- Report file download/content doesn't validate file path (potential directory traversal?)
- Update alert status endpoint lacks authentication entirely (line 579)
- Swagger/ReDoc docs are publicly accessible (no auth required)

---

### 3. `src/api/v1_router.py` - V1 Public API Router

**Purpose:** Protected V1 API for frontend applications, requiring JWT authentication from Repo 1.

**Application Architecture:**
- **Prefix:** `/api/v1`
- **Dependencies:** All endpoints depend on `verify_jwt` (protects entire router)
- **Auth:** JWT from Repo 1 (extracted via `oauth2_scheme`)

**Routes & Endpoints:**

| Endpoint | Method | Purpose | Dependencies |
|----------|--------|---------|--------------|
| `/api/v1/dashboard/summary` | GET | Comprehensive dashboard summary | `verify_jwt`, `get_tenant_id` |
| `/api/v1/logs` | GET | List normalized logs with pagination & filters | `verify_jwt`, `get_tenant_id` |
| `/api/v1/analytics/timeline` | GET | Event timeline for charts (24h, 7d, 30d) | `verify_jwt`, `get_tenant_id` |
| `/api/v1/analytics/threat-vectors` | GET | Top threat vectors by alert type | `verify_jwt`, `get_tenant_id` |
| `/api/v1/analytics/geo-distribution` | GET | Geographic distribution of events | `verify_jwt`, `get_tenant_id` |
| `/api/v1/analytics/traffic` | GET | Network traffic analysis by protocol | `verify_jwt`, `get_tenant_id` |
| `/api/v1/analytics/top-ips` | GET | Top source/destination IPs | `verify_jwt`, `get_tenant_id` |
| `/api/v1/analytics/business-insights` | GET | Business hours vs after-hours activity | `verify_jwt`, `get_tenant_id` |
| `/api/v1/alerts` | GET | List alerts with pagination & filtering | `verify_jwt`, `get_tenant_id` |
| `/api/v1/alerts/{alert_id}` | GET | Detailed alert info with related logs & recommendations | `verify_jwt`, `get_tenant_id` |
| `/api/v1/assets` | GET | List discovered assets with pagination | `verify_jwt`, `get_tenant_id` |
| `/api/v1/assets/summary` | GET | Asset inventory summary | `verify_jwt`, `get_tenant_id` |
| `/api/v1/assets/{device_id}` | GET | Detailed asset information | `verify_jwt`, `get_tenant_id` |

**Auth Mechanism:**
- **Type:** JWT Bearer token
- **Source:** OAuth2PasswordBearer from `/dashboard/login`
- **Verification:** `verify_jwt()` dependency applied to entire router
- **Tenant Isolation:** Multi-tenant via `tenant_id` query parameter (auth handled upstream by Repo 1)

**Key Dependencies:**

```python
def get_db():
    with db_manager.session_scope() as session:
        yield session

def get_tenant_id(tenant_id: str = Query("default")) -> str:
    return tenant_id
```

**Middleware:**
- None explicitly in this file (inherited from main.py)

**Response Format:**
- Standard: `ApiResponse(status="success", data=...)`
- Pagination format:
  ```json
  {
    "status": "success",
    "data": [...],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 100,
      "has_more": true
    },
    "timestamp": "2024-01-01T00:00:00"
  }
  ```

**Alert Detail Recommendations:**
- Brute force: Block IP, enable lockout, implement MFA
- Port scan: Block IP, review services, enable IDS/IPS
- Suspicious payload: Quarantine, scan systems, update signatures
- Beaconing: Block destination, scan host, review logs
- Threat intel match: Block indicator, investigate traffic, scan IoCs

**Filtering & Pagination:**
- Logs: severity, vendor, device_type, search
- Alerts: severity, status, alert_type
- Pagination: page (≥1), limit (1-100)

**TODOs/Missing Pieces:**
```python
# Line 13: Imports verify_jwt from src.api.auth
# but authentication is supposed to be "managed by Repo 1"
# Question: Is token issued by Repo 1 or generated locally?

# Line 121: AnalyticsService methods called but implementation details not shown
# Need to verify these services exist and are properly implemented

# Lines 327-371: _generate_recommendations() is hardcoded
# Should be more flexible or database-driven
```

**Security Notes:**
- All endpoints protected by JWT dependency
- Tenant isolation relies on `tenant_id` parameter and Repo 1 validation
- No additional authorization checks beyond JWT presence
- Alert recommendations are static (not personalized)

---

### 4. `src/api/admin_router.py` - Admin & Service-to-Service Router

**Purpose:** Admin API for service-to-service communication with Repo 1 and per-tenant analytics.

**Application Architecture:**
- **Prefix:** `/api/admin`
- **Auth Methods:** Dual authentication support
  - `X-Admin-Key` header (shared secret between services)
  - JWT Superadmin token (from `verify_superadmin`)

**Routes & Endpoints:**

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/admin/tenants/{tenant_id}/usage` | GET | Admin or Superadmin | Per-tenant usage statistics |
| `/api/admin/system/overview` | GET | Admin or Superadmin | System-wide statistics across all tenants |
| `/api/admin/proxy/login` | POST | None | Proxy login to Repo 1 (CORS bypass) |
| `/api/admin/config/verify-sync` | GET | Superadmin only | Verify SECRET_KEY sync with Repo 1 |
| `/api/admin/allowlist/{tenant_id}` | GET | Superadmin only | Get IP allowlist from Repo 1 |
| `/api/admin/allowlist/{tenant_id}` | POST | Superadmin only | Add IP to allowlist in Repo 1 |
| `/api/admin/allowlist/{tenant_id}/{ip}` | DELETE | Superadmin only | Remove IP from allowlist in Repo 1 |
| `/api/admin/tenants/sync` | POST | Admin key only | Webhook for Repo 1 to sync tenant data |
| `/api/admin/proxy/{path}` | GET, POST, PUT, DELETE | Superadmin | Generic proxy for Repo 1 endpoints |

**Auth Mechanisms:**

1. **Admin Key (X-Admin-Key Header):**
   ```python
   def verify_admin_key(x_admin_key: str = Header(...)) -> str:
       expected = os.getenv("ADMIN_API_KEY", "changeme-admin-key")
       if x_admin_key != expected:
           raise HTTPException(status_code=403, detail="Invalid admin API key")
   ```

2. **Superadmin or Admin Key:**
   ```python
   def verify_admin_or_superadmin(
       x_admin_key: Optional[str] = Header(None),
       jwt_payload: Optional[dict] = Depends(verify_superadmin)
   ):
       if x_admin_key == expected:
           return True
       if jwt_payload:  # Superadmin JWT
           return True
       raise HTTPException(status_code=401)
   ```

**Tenant Usage Endpoint (`/api/admin/tenants/{tenant_id}/usage`):**
- Returns:
  - Log counts: total, last 24h, last 7d
  - Alert counts: total, active, by severity
  - Report count
  - Dead letter count
  - Estimated storage (500 bytes per log)
  - Tenant metadata (name, active status, created_at)

**System Overview Endpoint (`/api/admin/system/overview`):**
- Returns:
  - Total tenants (active/inactive)
  - Global counts (logs, alerts, reports, dead letters)
  - Last 24h activity
  - Alert severity breakdown
  - Top 20 tenants by log volume

**Proxy Endpoints:**

1. **Login Proxy:**
   - Forwards login to Repo 1: `{REPO1_BASE_URL}/admin/login`
   - Handles CORS issues between frontend and Repo 1
   - Logs response metadata (status, keys, token presence)

2. **Config Verify Sync:**
   - Calls `{REPO1_BASE_URL}/admin/auth/jwt-public-config`
   - Compares algorithm (expects HS256)
   - Compares env var names
   - Returns local vs Repo 1 config comparison

3. **Allowlist Proxies:**
   - GET/POST/DELETE to Repo 1 allowlist endpoints
   - Adapts Repo 1 format (`ip_ranges`, `entries`) to dashboard format

4. **Generic Proxy:**
   - Forwards any request to Repo 1 under `/api/admin/proxy/{path}`
   - Maintains Authorization header
   - Returns response as-is
   - Requires Superadmin JWT

**Tenant Sync Webhook:**
- Receives events from Repo 1: `tenant.created`, `tenant.updated`, `tenant.deleted`
- Creates/updates/deactivates tenants locally
- Protected by admin key (service-to-service communication)

**Middleware:**
- None explicitly (inherited from main.py)

**TODOs/Missing Pieces:**
```python
# Line 256-287: proxy_login() endpoint is public (no auth)
# Should probably require admin key at minimum

# Lines 288-320: verify_repo1_sync() endpoint uses hardcoded URL path
# "/admin/auth/jwt-public-config" may not exist or may be different

# Lines 321-349: Allowlist proxies assume Repo 1 response format
# No validation or error handling for format mismatches

# Line 429: Generic proxy endpoint requires Superadmin JWT
# but tenant sync webhook requires only admin key
# Inconsistent auth levels

# Missing: Direct tenant creation/deletion endpoints
# All tenant management delegates to Repo 1

# Missing: Health check endpoint for service connectivity
```

**Security Notes:**
- Admin key is shared in plain X-Admin-Key header (requires HTTPS in production)
- Default admin key: `"changeme-admin-key"` (obvious development default)
- Proxy endpoints forward all headers/bodies to Repo 1
- Tenant sync webhook doesn't verify Repo 1's identity (only checks admin key)
- Generic proxy could forward sensitive requests if Superadmin JWT is compromised

---

### 5. `src/utils/auth.py` - Utility Authentication Functions

**Purpose:** Legacy/alternative authentication utilities (not used in main routers).

**Functions:**

| Function | Purpose | Algorithm |
|----------|---------|-----------|
| `verify_password(plain, hashed)` | Check password against hash | PBKDF2-SHA256 |
| `get_password_hash(password)` | Hash a password | PBKDF2-SHA256 |
| `create_access_token(data, expires_delta)` | Create JWT token | HS256 |
| `decode_access_token(token)` | Decode and verify JWT | HS256 |
| `get_current_user(token, token_query)` | FastAPI dependency for auth | Bearer token |

**Key Configuration:**
```python
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
```

**OAuth2 Scheme:**
```python
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)
```

**get_current_user() Dependency:**
- Accepts token from header or query parameter (`token` query alias)
- Returns `CurrentUser` object with:
  - `username` (from `sub` claim)
  - `role` (from `role` claim)
  - `tenant_id` (from `tenant_id` claim, default: `"default"`)
- Raises HTTP 401 if token missing or invalid

**TODOs/Missing Pieces:**
```python
# Lines 40-81: This entire module appears to be legacy code
# Not imported or used anywhere in main.py, v1_router.py, or admin_router.py
# Real auth is done in src/api/auth.py instead

# Line 10: Default SECRET_KEY is obviously fake
# "your-secret-key-change-this-in-production"
# This should never be used in production

# Line 44: oauth2_scheme tokenUrl is "auth/login"
# but the actual endpoint is at "/dashboard/login" (from api/auth.py)
# Inconsistent endpoint references

# Lines 75-81: CurrentUser class defined inline
# Should be moved to models/schemas.py for reusability
```

**Security Notes:**
- This module uses the same HS256 algorithm as `src/api/auth.py`
- Password hashing is separate from JWT (good separation of concerns)
- Not currently integrated into request flow (dead code?)
- Default secret key is highly visible (security concern if accidentally used)

---

### 6. `src/main.py` - Application Entry Point

**Purpose:** Main application class and entry point for the SIEM analyzer.

**SIEMAnalyzer Class:**

**Initialization & Startup:**
- Initializes database
- Registers threat analyzers:
  - BruteForceAnalyzer
  - PortScanAnalyzer
  - ThreatIntelAnalyzer
  - BeaconingAnalyzer
  - PayloadAnalysisAnalyzer
- Initializes Redis consumer (listens to message queue)
- Initializes task scheduler

**Threads:**
- **Main thread:** Handles signals (SIGINT, SIGTERM)
- **Redis Consumer thread:** Processes messages from Redis queue
- **API Server thread:** Runs FastAPI/Uvicorn on port 8000, host 0.0.0.0

**Logging Output on Startup:**
```
Redis queue: {config.redis_queue_pattern}
Database: {config.database_type}
Email alerts: {enabled/disabled}
Reports: {enabled/disabled}
```

**Graceful Shutdown:**
- Sets `running = False`
- Stops Redis consumer
- Stops scheduler
- Closes database connections
- Waits up to 5 seconds for consumer thread to finish

**No Direct Auth in this file:**
- Auth is handled entirely by FastAPI routers
- No middleware or dependencies at this level

**TODOs/Missing Pieces:**
```python
# No explicit error handling for:
# - Redis connection failures
# - Database initialization failures
# - Analyzer registration failures
# Errors are caught but only logged, doesn't prevent startup

# Line 102: Uvicorn config is hardcoded to port 8000, host 0.0.0.0
# Should be configurable via config.py

# No health check endpoint in the main analyzer
# Only the API server has health endpoints
```

---

## Authentication & Authorization Summary

### Auth Mechanisms Used:

| Mechanism | Location | Purpose | Key/Token Source |
|-----------|----------|---------|-------------------|
| **JWT (HS256)** | `src/api/auth.py` | V1 API & Admin endpoints | `config.secret_key` (from Repo 1) |
| **Admin Key (Header)** | `src/api/admin_router.py` | Service-to-service & admin endpoints | `ADMIN_API_KEY` env var (default: `changeme-admin-key`) |
| **OAuth2 Bearer** | V1 & Auth routers | Token transport mechanism | Issued by Repo 1 or generated locally |
| **Password Hash** | `src/utils/auth.py` (legacy) | User authentication | PBKDF2-SHA256 (not currently used) |

### JWT Claims Used:

```python
{
    "sub": "username",           # Subject (from get_current_user)
    "username": "username",      # Username
    "email": "user@example.com", # Email (for admin detection)
    "role": "superadmin",        # Role ("superadmin" for admin access)
    "is_admin": true,            # Admin flag
    "tenant_id": "tenant-1",     # Tenant identifier
    "exp": 1234567890,           # Expiration timestamp
    
    # Nested admin object (for Repo 1 compatibility)
    "admin": {
        "username": "superadmin",
        "role": "superadmin",
        "is_admin": true
    }
}
```

### Protected Endpoints by Auth Type:

**JWT + Tenant ID (V1 API):**
- `/api/v1/dashboard/summary`
- `/api/v1/logs`
- `/api/v1/alerts*`
- `/api/v1/analytics/*`
- `/api/v1/assets*`

**Admin Key (Main endpoints & internal use):**
- `/stats`
- `/alerts` (main)
- `/logs` (main)
- `/reports*`
- `/analytics/*` (main)
- `/config`
- `/trends`
- `/api/dashboard-summary`

**Admin Key OR Superadmin JWT (Admin router):**
- `/api/admin/tenants/{tenant_id}/usage`
- `/api/admin/system/overview`

**Admin Key Only (Webhooks):**
- `/api/admin/tenants/sync` (Repo 1 webhook)

**Superadmin JWT Only (Admin router):**
- `/api/admin/config/verify-sync`
- `/api/admin/allowlist/*`
- `/api/admin/proxy/*`

**Public/No Auth:**
- `/docs`
- `/redoc`
- `/openapi.json`
- `/static/*`
- `/dashboard/*`
- `/api/admin/proxy/login`
- `/alerts/{alert_id}` (PATCH, no auth required—potential vulnerability)

---

## Configuration & Environment Variables

| Variable | Used In | Default | Purpose |
|----------|---------|---------|---------|
| `SECRET_KEY` | `src/api/auth.py`, `src/utils/auth.py` | `"changeme-admin-key"` or fallback | JWT signing/verification secret |
| `ADMIN_API_KEY` | `src/api/admin_router.py` | `"changeme-admin-key"` | X-Admin-Key header validation |
| `ALLOWED_ORIGINS` | `src/api/main.py` | `"http://localhost:3000,http://localhost:8000"` | CORS allowed origins |
| `REPO1_BASE_URL` | `src/api/admin_router.py` | `"http://host.docker.internal:8080"` | Repo 1 service URL for proxying |
| `DATABASE_URL` | `src/api/main.py` lifespan | None (uses config.py) | Database connection string |

---

## Middleware Stack (in order)

1. **SlowAPI Rate Limiting Middleware** - Request throttling
2. **CORS Middleware** - Cross-origin requests
3. **Security Headers Middleware** - Security headers (CSP, X-Frame-Options, etc.)
4. **Global Exception Handler** - Catch-all error handling
5. **Static Files Mount** - Serve assets without middleware processing
6. **Lifespan Handler** - App startup/shutdown

---

## Key Security Findings

### ✅ Strengths:
1. JWT verification with fail-secure approach (denies access if secret missing)
2. Rate limiting on sensitive endpoints
3. Security headers properly configured
4. Multi-level authentication (JWT + Admin key)
5. Superadmin role-based access control
6. CORS properly configured

### ⚠️ Weaknesses & TODOs:
1. **Default admin keys in code** - `"changeme-admin-key"` is obvious
2. **Admin key in header (not secure without HTTPS)** - No encryption in transit
3. **Public alert update endpoint** - PATCH `/alerts/{alert_id}` has no auth
4. **Swagger UI public** - `/docs` exposed without auth (may leak API schema)
5. **JWT claims details in error messages** - Unverified payload leaked in 401 responses
6. **Legacy auth code in `src/utils/auth.py`** - Unused, confusing
7. **Inconsistent auth levels** - Some endpoints admin-key, some JWT, some none
8. **No input validation on tenant_id** - Could be bypass vector
9. **Direct file operations** - Report download doesn't validate file paths
10. **Hardcoded Repo 1 URL paths** - Fragile if Repo 1 API changes
11. **No request signing** - Webhook from Repo 1 (tenant sync) only checks admin key
12. **Token forwarding** - Proxy endpoints forward auth headers to Repo 1 (trust boundary)

### 🔧 Missing Pieces:
1. **API Key rotation mechanism** - No versioning or expiration for admin keys
2. **Audit logging** - No audit trail for admin operations
3. **Request validation** - No schema validation for webhook payloads
4. **Health checks** - No `/health` endpoint for monitoring
5. **Rate limit per tenant** - Currently global by IP only
6. **Token revocation** - No blacklist or revocation mechanism
7. **HTTPS enforcement** - No scheme validation in config
8. **CSRF protection** - Not mentioned in middleware
9. **SQL injection protection** - SQLAlchemy ORM used (good), but raw SQL in some places
10. **Encryption at rest** - No mention of database encryption

---

## Dependency Flow

```
src/main.py (Entry Point)
├── Initialize db_manager
├── Register analyzers
├── Start RedisConsumer thread
├── Start Scheduler thread
└── Start API Server (src/api/main.py)
    ├── Register routes
    │   ├── src/api/v1_router.py (JWT protected)
    │   ├── src/api/admin_router.py (Admin key or Superadmin JWT)
    │   └── src/api/health.py (No auth)
    ├── Middleware
    │   ├── CORSMiddleware
    │   ├── SlowAPI (Rate Limiting)
    │   └── Security Headers
    └── Auth
        ├── src/api/auth.py (verify_jwt, verify_superadmin)
        └── src/utils/auth.py (Legacy, unused)
```

---

## Repo 1 Integration Points

1. **Login:** `/api/admin/proxy/login` → Proxies to `{REPO1_BASE_URL}/admin/login`
2. **Config Sync:** `/api/admin/config/verify-sync` → Calls `{REPO1_BASE_URL}/admin/auth/jwt-public-config`
3. **IP Allowlist:** `/api/admin/allowlist/*` → Proxies to `{REPO1_BASE_URL}/admin/allowlist/*`
4. **Tenant Sync Webhook:** Repo 1 → `/api/admin/tenants/sync` (POST with admin key)
5. **JWT Verification:** Repo 1 issues tokens, Repo 2 verifies with `config.secret_key`
6. **Generic Proxy:** `/api/admin/proxy/{path}` → Forwards to `{REPO1_BASE_URL}/{path}`

**Assumptions:**
- Repo 1 and Repo 2 share the same `SECRET_KEY` in .env
- Repo 1 issues HS256-signed JWT tokens
- Repo 1 hosts admin endpoints at documented paths
- Tenant data is synchronized via webhook events

