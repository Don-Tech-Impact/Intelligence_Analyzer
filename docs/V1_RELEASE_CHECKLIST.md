# V1 Release Checklist - afric-analyzer

## 📅 Target Release: V1.0.0
## 📊 Status: Implementation Complete

---

## ✅ Required Endpoints

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/auth/login` | POST | User authentication | ✅ Existing |
| `/health` | GET | Full health check with component status | ✅ NEW |
| `/health/live` | GET | Kubernetes liveness probe | ✅ NEW |
| `/health/ready` | GET | Kubernetes readiness probe | ✅ NEW |
| `/metrics` | GET | Prometheus metrics | ✅ NEW |
| `/metrics/json` | GET | JSON metrics | ✅ NEW |
| `/api/v1/dashboard/summary` | GET | Dashboard summary cards | ✅ NEW |
| `/api/v1/analytics/timeline` | GET | Event timeline chart data | ✅ NEW |
| `/api/v1/analytics/threat-vectors` | GET | Top threat types | ✅ NEW |
| `/api/v1/analytics/geo-distribution` | GET | Geographic distribution | ✅ NEW |
| `/api/v1/analytics/traffic` | GET | Network traffic by protocol | ✅ NEW |
| `/api/v1/alerts` | GET | List alerts with pagination | ✅ NEW |
| `/api/v1/alerts/{id}` | GET | Alert detail with related logs | ✅ NEW |
| `/api/v1/assets` | GET | List discovered assets | ✅ NEW |
| `/api/v1/assets/summary` | GET | Asset inventory summary | ✅ NEW |
| `/api/v1/assets/{id}` | GET | Asset detail | ✅ NEW |

---

## ✅ Required Database Tables

| Table | Purpose | Status |
|-------|---------|--------|
| `logs` (NormalizedLog) | Store normalized log entries | ✅ Existing |
| `alerts` | Store generated alerts | ✅ Existing |
| `threat_intelligence` | Threat intel indicators | ✅ Existing |
| `tenants` | Multi-tenant configuration | ✅ Existing |
| `users` | User accounts | ✅ Existing |
| `reports` | Generated reports | ✅ Existing |

### Database Indexes (Optimized for V1)

| Index | Purpose | Status |
|-------|---------|--------|
| `idx_tenant_timestamp` | Dashboard timeline queries | ✅ Existing |
| `idx_tenant_vendor` | Asset type aggregation | ✅ NEW |
| `idx_tenant_severity` | Threat breakdown | ✅ NEW |
| `idx_tenant_status_severity` | Alert filtering | ✅ NEW |
| `idx_source_ip_timestamp` | IP-based correlation | ✅ Existing |

---

## ✅ Required Intelligence Functions

| Function | Description | Status |
|----------|-------------|--------|
| Brute Force Detection | Detect repeated failed logins | ✅ Existing |
| Port Scan Detection | Detect port scanning activity | ✅ Existing |
| Threat Intel Matching | Match IPs against threat feeds | ✅ Existing |
| Payload Analysis | Detect suspicious payloads | ✅ Existing |
| Beaconing Detection | Detect C2 beaconing patterns | ✅ Existing |
| GeoIP Enrichment | Add geographic metadata | ✅ Existing |
| Threat Scoring | Calculate risk scores | ✅ Existing |
| Asset Discovery | Derive assets from device_id | ✅ NEW |

---

## ✅ Required Services

| Service | File | Purpose | Status |
|---------|------|---------|--------|
| AnalyticsService | `src/services/analytics.py` | Dashboard aggregations | ✅ NEW |
| AssetService | `src/services/assets.py` | Asset inventory | ✅ NEW |
| EnrichmentService | `src/services/enrichment.py` | Log enrichment | ✅ Existing |
| AnalysisPipeline | `src/services/log_ingestion.py` | Log processing | ✅ Existing |
| RedisConsumer | `src/services/redis_consumer.py` | Queue consumption | ✅ Existing |

---

## ✅ Required Tests

| Test Suite | File | Coverage | Status |
|------------|------|----------|--------|
| V1 API Tests | `tests/test_v1_api.py` | All V1 endpoints | ✅ NEW |
| Normalization Tests | `tests/test_normalization.py` | Log normalization | ✅ Existing |
| API Tests | `tests/test_api.py` | Legacy endpoints | ✅ Existing |
| Alert Tests | `tests/test_alert_management.py` | Alert CRUD | ✅ Existing |

---

## ✅ Required Docker Setup

| Component | File | Purpose | Status |
|-----------|------|---------|--------|
| Multi-stage Dockerfile | `Dockerfile` | Production & dev builds | ✅ UPDATED |
| Docker Compose | `docker-compose.yml` | Local development | ✅ UPDATED |
| Health Checks | Dockerfile + compose | Container health | ✅ UPDATED |
| Non-root User | Dockerfile | Security | ✅ UPDATED |
| Consumer Worker | docker-compose | Background processing | ✅ NEW |

---

## ✅ Required CI/CD

| Stage | Purpose | Status |
|-------|---------|--------|
| Lint (flake8) | Code style | ✅ Existing |
| Security Scan (bandit) | Vulnerability check | ✅ Existing |
| Unit Tests | Code coverage | ✅ UPDATED |
| Coverage Report | Codecov upload | ✅ NEW |
| Docker Build (production) | Build validation | ✅ UPDATED |
| Docker Build (development) | Dev image | ✅ NEW |
| API Integration Tests | Endpoint validation | ✅ NEW |

---

## ✅ Required Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | `sqlite:///siem_analyzer.db` | Database connection |
| `REDIS_URL` | Yes | `redis://localhost:6379/0` | Redis connection |
| `REDIS_LOG_QUEUE` | Yes | `log_queue` | Redis queue name |
| `SECRET_KEY` | Yes | - | JWT signing key |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` | CORS origins |

---

## 📋 Pre-Release Validation

### Local Testing
```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/test_v1_api.py -v

# Start API
uvicorn src.api.main:app --reload

# Test endpoints
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

### Docker Testing
```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Check health
curl http://localhost:8000/health

# View logs
docker-compose logs -f analyzer
```

### API Validation
```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -d "username=admin&password=admin123"

# Dashboard summary (replace TOKEN)
curl http://localhost:8000/api/v1/dashboard/summary \
  -H "Authorization: Bearer TOKEN"

# Timeline
curl "http://localhost:8000/api/v1/analytics/timeline?range=24h&bucket=hour" \
  -H "Authorization: Bearer TOKEN"
```

---

## 🚀 Deployment Steps

1. **Create `.env` file** with production secrets
2. **Run database migrations** (SQLAlchemy auto-creates tables)
3. **Build Docker image**: `docker-compose build`
4. **Start services**: `docker-compose up -d`
5. **Verify health**: `curl http://localhost:8000/health`
6. **Create admin user** (auto-created on first start)
7. **Configure Prometheus** to scrape `/metrics`

---

## 📊 Frontend Integration Points

| Frontend Widget | API Endpoint | Notes |
|-----------------|--------------|-------|
| Summary Cards | `GET /api/v1/dashboard/summary` | Total events, threats, risk score |
| Timeline Chart | `GET /api/v1/analytics/timeline` | Support 24h/7d/30d ranges |
| Threat Vectors | `GET /api/v1/analytics/threat-vectors` | Top N threat types |
| Geo Map | `GET /api/v1/analytics/geo-distribution` | Country codes for mapping |
| Traffic Chart | `GET /api/v1/analytics/traffic` | Protocol breakdown |
| Alerts Table | `GET /api/v1/alerts` | Paginated with filters |
| Alert Detail | `GET /api/v1/alerts/{id}` | Related logs + recommendations |
| Assets Table | `GET /api/v1/assets` | Device inventory |
| Asset Detail | `GET /api/v1/assets/{id}` | Full device info |

---

## ✅ V1 Scope Exclusions (Deferred to V2)

| Feature | Reason |
|---------|--------|
| ML-based Anomaly Detection | Requires training data |
| LLM Reasoning | Requires API integration |
| Redis Streams | BLPOP sufficient for V1 volumes |
| Real-time WebSockets | SSE/polling sufficient for V1 |
| Advanced Correlation | Rule-based correlation sufficient |

---

## 📝 Sign-off

- [ ] All endpoints implemented and tested
- [ ] Docker images build successfully
- [ ] CI/CD pipeline passes
- [ ] Health checks working
- [ ] Metrics endpoint functional
- [ ] Documentation updated
- [ ] Frontend developer briefed on API contract

**V1 Status: READY FOR INTEGRATION TESTING**
