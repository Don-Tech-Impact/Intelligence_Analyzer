# Afric-Analyzer — Complete Architecture & Deployment Plan

> **Three Services:** Repo1 (Ingestion + Admin, :8080) → Redis → Repo2 (Analysis + Dashboard, :8000) + Frontend (React)

---

## 1. System Architecture — How the Pieces Fit

### Data Flow

```
External Logs                    ┌─────────────────────────┐
(Firewalls, IDS, etc.)           │      REPO 1 (:8080)     │
        │                        │  Afric Analyzer          │
        ▼                        │  ─────────────────────── │
  POST /api/logs/ingest ───────► │  • Log ingestion         │
  POST /api/logs/batch           │  • API key auth          │
  (X-API-Key header)             │  • Rate limiting         │
                                 │  • IP allowlist check    │
                                 │  • SuperAdmin CRUD       │
                                 │  • Tenant management     │
                                 │  • Auto-scaling workers  │
                                 └────────┬────────────────┘
                                          │ Redis Queues
                           logs:{tenant}:ingest → clean → dead
                                          │
                                 ┌────────▼────────────────┐
                                 │      REPO 2 (:8000)     │
                                 │  Intelligence Analyzer   │
                                 │  ─────────────────────── │
                                 │  • Redis consumer        │
                                 │  • Log normalization     │
                                 │  • Threat detection      │
                                 │  • Alert generation      │
                                 │  • Analytics / Reports   │
                                 │  • Dashboard (static)    │
                                 │  • V1 API for frontend   │
                                 └────────┬────────────────┘
                                          │
                                 ┌────────▼────────────────┐
                                 │    FRONTEND (React)      │
                                 │  Built by frontend team  │
                                 │  Consumes /api/v1/*      │
                                 └─────────────────────────┘
```

### Key Insight: No HTTP Between Repo1 ↔ Repo2

Repo1 and Repo2 communicate **exclusively via Redis queues** — not HTTP.
- Repo1 **produces** logs into `logs:{tenant_id}:ingest`
- Repo2 **consumes** logs from those queues
- Both services connect to the **same Redis instance**
- Tenant isolation happens at the queue level (`logs:tenant123:ingest`)

---

## 2. Repo1 API Reference (Port 8080)

### Public (No Auth)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Service info |
| `GET` | `/health` | Health check (Redis + publisher) |
| `GET` | `/metrics` | Prometheus metrics (queue depths, worker backlog) |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc |

### Log Ingestion (API Key: `X-API-Key` header)
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/logs/ingest` | Ingest single log (100 req/min) |
| `POST` | `/api/logs/batch` | Ingest batch (50 req/min, max 1000) |
| `GET` | `/api/logs/schema` | Get expected schema + examples |
| `GET` | `/api/logs/health` | Ingestion component health |
| `GET` | `/api/logs/metrics` | Ingestion Prometheus metrics |

### SuperAdmin (JWT: `Authorization: Bearer <token>`)
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/admin/login` | Login → JWT |
| `POST` | `/admin/logout` | Invalidate JWT |
| `GET` | `/admin/tenants` | List all tenants |
| `POST` | `/admin/tenants` | Create tenant |
| `GET` | `/admin/tenants/{id}` | Tenant details |
| `PUT` | `/admin/tenants/{id}` | Update tenant |
| `DELETE` | `/admin/tenants/{id}` | Soft-delete tenant |
| `POST` | `/admin/tenants/{id}/api-keys` | Create API key |
| `GET` | `/admin/tenants/{id}/api-keys` | List API keys |
| `PUT` | `/admin/api-keys/{key_id}` | Update key |
| `DELETE` | `/admin/api-keys/{key_id}` | Delete key |
| `POST` | `/admin/tenants/{id}/ips` | Add IP to allowlist |
| `GET` | `/admin/tenants/{id}/ips` | List allowed IPs |
| `DELETE` | `/admin/ips/{ip_id}` | Remove IP |
| `GET` | `/admin/audit-log` | Paginated audit log |

### Repo1 Security
| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | `default-src 'self'` |
| `X-Request-ID` | UUID per request |
| `X-Process-Time` | Request duration |

### Repo1 Rate Limits
| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/logs/ingest` | 100 req | 1 minute |
| `/api/logs/batch` | 50 req | 1 minute |
| `/api/logs/schema` | 200 req | 1 minute |

---

## 3. Repo2 API Reference (Port 8000)

### Public
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Health check (DB + Redis) |
| `GET` | `/health/live` | K8s liveness probe |
| `GET` | `/health/ready` | K8s readiness probe |
| `GET` | `/metrics` | Prometheus metrics (DB stats, queue size) |
| `GET` | `/metrics/json` | JSON metrics |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc |

### Legacy Dashboard Endpoints (used by built-in dashboard at `/dashboard/`)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/stats` | High-level statistics |
| `GET` | `/alerts` | Recent alerts (filterable) |
| `GET` | `/logs` | Recent logs (filterable, searchable) |
| `GET` | `/trends` | Chart data (24h timeline) |
| `GET` | `/analytics/top-ips` | Top source/dest IPs |
| `GET` | `/analytics/protocols` | Protocol distribution |
| `GET` | `/analytics/business-insights` | Business hour analysis |
| `GET` | `/reports` | List reports |
| `GET` | `/reports/{id}/download` | Download report file |
| `GET` | `/config` | SIEM config |
| `POST` | `/config` | Update SIEM config |
| `PATCH` | `/alerts/{id}/status` | Update alert status |
| `GET` | `/api/dashboard-summary` | Full dashboard in one call |

### V1 API (for React frontend team — standardized envelope)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/dashboard/summary` | Full dashboard in one call |
| `GET` | `/api/v1/analytics/timeline` | Event timeline (24h/7d/30d) |
| `GET` | `/api/v1/analytics/threat-vectors` | Top threats by type |
| `GET` | `/api/v1/analytics/geo-distribution` | Geographic breakdown |
| `GET` | `/api/v1/analytics/traffic` | Protocol traffic analysis |
| `GET` | `/api/v1/alerts` | Paginated alerts with filters |
| `GET` | `/api/v1/alerts/{id}` | Alert detail + related logs + recommendations |
| `GET` | `/api/v1/assets` | Paginated assets |
| `GET` | `/api/v1/assets/summary` | Asset inventory summary |
| `GET` | `/api/v1/assets/{device_id}` | Asset detail |

### Static Files
| Path | Content |
|------|---------|
| `/dashboard/` | Built-in SIEM dashboard (HTML/CSS/JS) |
| `/static/` | Swagger UI assets |

---

## 4. API Standards (For Frontend Team)

### Standard Response Envelope (V1 only)
```json
{
  "status": "success",
  "data": { ... },
  "message": "Optional human-readable",
  "timestamp": "2026-02-21T16:00:00Z"
}
```

### Paginated Response
```json
{
  "status": "success",
  "data": [ ... ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 142,
    "has_more": true
  },
  "timestamp": "2026-02-21T16:00:00Z"
}
```

### Error Response
```json
{
  "detail": "What went wrong"
}
```

HTTP status codes: `400` validation, `401` no auth, `403` forbidden, `404` not found, `429` rate limited, `500` server error

### Frontend Auth Flow
1. **Admin users** → `POST /admin/login` on Repo1 → JWT
2. **Tenant users** → authenticate via Repo1 → JWT with `tenant_id` claim
3. **Frontend** → calls Repo2 V1 API with `?tenant_id=xxx` query param
4. Repo2 trusts the `tenant_id` (auth validated upstream by Repo1 / ALB)

---

## 5. SuperAdmin Dashboard — What You Need

Repo1 **already has the complete admin API**. What's needed:

### In Repo1 (Admin Platform) — Build SuperAdmin UI
A **SuperAdmin SPA** that consumes Repo1's own `/admin/*` endpoints:
- **Tenant list page** → `GET /admin/tenants`
- **Create tenant form** → `POST /admin/tenants`
- **Tenant detail page** → `GET /admin/tenants/{id}` + API keys + IPs
- **Audit log page** → `GET /admin/audit-log`

### In Repo2 (Intelligence Analyzer) — NEW: Tenant Stats API
Repo1's admin dashboard will need **per-tenant analytics** from Repo2:

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| `GET` | `/api/admin/tenants/{id}/usage` | Logs count, alerts, storage | `X-Admin-Key` |
| `GET` | `/api/admin/system/overview` | Total tenants, logs, alerts, uptime | `X-Admin-Key` |

These endpoints are called **server-to-server** by Repo1 using a shared `X-Admin-Key` secret.

---

## 6. AWS Deployment Checklist

### ALB Path-Based Routing

| Priority | Path Pattern | Target | Port |
|----------|-------------|--------|------|
| 1 | `/admin/*` | Repo1 (ECS) | 8080 |
| 2 | `/api/logs/*` | Repo1 (ECS) | 8080 |
| 3 | `/api/v1/*` | Repo2 (ECS) | 8000 |
| 4 | `/stats`, `/alerts`, `/logs`, `/trends`, `/analytics/*`, `/config`, `/reports*` | Repo2 (ECS) | 8000 |
| 5 | `/health*`, `/metrics*` | Repo2 (ECS) | 8000 |
| 6 | `/dashboard/*` | Repo2 (ECS) | 8000 |
| 7 | `/*` (default) | Frontend (Nginx) | 80 |

> **Note:** Repo1 health (`/health`) conflicts with Repo2 health. In production, prefix Repo1 health as `/r1/health` or use separate subdomains (`api.example.com` for Repo1, `engine.example.com` for Repo2).

### Phase 1: Infrastructure
- [ ] VPC with public + private subnets (2 AZs min)
- [ ] Security Groups:
  - ALB SG: 80/443 from 0.0.0.0/0
  - ECS SG: traffic only from ALB SG
  - RDS SG: 5432 only from ECS SG
  - Redis SG: 6379 only from ECS SG
- [ ] RDS PostgreSQL `db.t3.medium`, multi-AZ, automated backups, encryption at rest
- [ ] ElastiCache Redis `cache.t3.micro` (**shared** between Repo1 + Repo2)
- [ ] ACM SSL certificate for domain

### Phase 2: Container Setup
- [ ] ECR: 3 repositories (repo1, repo2, frontend)
- [ ] Dockerfiles:
  - Repo1: `python:3.11-slim` + requirements (includes auto-scaling workers)
  - Repo2: `python:3.11-slim` + requirements (includes redis-consumer process)
  - Frontend: `nginx:alpine` + static build
- [ ] ECS Cluster (Fargate launch type)
- [ ] Task Definitions:
  - Repo1: 512 CPU / 1024 MB
  - Repo2: 1024 CPU / 2048 MB (heavier analysis workload)
  - Frontend: 256 CPU / 512 MB

### Phase 3: Load Balancer
- [ ] ALB (internet-facing), HTTPS with ACM cert
- [ ] 3 Target Groups (one per service)
- [ ] Path-based listener rules per routing table
- [ ] Health checks:
  - Repo1: `GET /health` (port 8080)
  - Repo2: `GET /health` (port 8000)
  - Frontend: `GET /` (port 80)

### Phase 4: Secrets & Config
- [ ] **AWS Secrets Manager:**
  - `DATABASE_URL` → RDS endpoint
  - `REDIS_URL` → ElastiCache endpoint
  - `ADMIN_API_KEY` → shared Repo1↔Repo2 secret
  - `JWT_SECRET` → Repo1 JWT signing key
  - `ADMIN_EMAIL` / `ADMIN_PASSWORD` → superadmin bootstrap
- [ ] **Environment variables** per task definition:
  - `ALLOWED_ORIGINS` → production domain
  - `LOG_LEVEL` → `INFO` for prod
- [ ] **CloudWatch Log Groups** per service

### Phase 5: DNS & CDN
- [ ] Route 53: `yourdomain.com` → ALB alias record
- [ ] **CloudFront** (optional): Cache `/dashboard/*` and frontend static assets
- [ ] Consider subdomain split if routing gets complex:
  - `app.yourdomain.com` → Frontend
  - `api.yourdomain.com` → Repo1 + Repo2

### Phase 6: CI/CD (GitHub Actions)
- [ ] **Per-repo pipeline:**
  1. Run tests (`pytest` / `npm test`)
  2. Build Docker image
  3. Push to ECR
  4. Update ECS service (rolling deploy)
- [ ] **Database migrations:** ECS `run-task` for migration commands
- [ ] **Environment promotion:** staging → production with approval gate

### Phase 7: Monitoring & Alerts
- [ ] **CloudWatch Alarms:**
  - CPU utilization > 80%
  - Memory utilization > 80%
  - 5xx error rate > 10/min
  - Unhealthy target count > 0
- [ ] **Prometheus scraping:**
  - Repo1: `/metrics` (queue depths, worker backlog)
  - Repo2: `/metrics` (DB stats, queue sizes)
- [ ] **Log-based alerts:** Error rate spikes, failed log ingestion
- [ ] **Redis monitoring:** Queue depth alerts (dead letter queue growth)
