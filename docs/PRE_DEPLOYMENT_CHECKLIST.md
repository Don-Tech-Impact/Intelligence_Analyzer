# Pre-Deployment Checklist: Intelligence Analyzer

This checklist ensures that the Intelligence Analyzer (Repo 2) is production-ready for deployment on AWS with containerized services.

## 1. Code Quality & Testing
- [x] **Full Test Suite**: All 86 tests passed successfully (`python -m pytest tests/`).
- [x] **Multi-Tenant Isolation**: Verified `tests/test_tenant_isolation.py` to prevent data leakage between companies.
- [x] **Linting**: No critical code issues in main application routers.

## 2. Security & Credentials
- [ ] **Environment Variables**: Use an AWS Secret Manager or Parameter Store for production `.env` values.
    - [ ] `SECRET_KEY`: Generate a unique, cryptographically strong string.
    - [ ] `ADMIN_API_KEY`: Change from `changeme-admin-key` to a secure production key.
    - [ ] `DATABASE_URL`: Ensure it points to a persistent RDS instance or a managed volume if using SQLite.
- [ ] **Firewall (Security Groups)**:
    - [ ] Port `8000`: Restricted to Load Balancer or specific CIDR.
    - [ ] Port `6379`: **Internal only**. Must not be exposed to the public internet.

## 3. Container Orchestration (AWS)
- [ ] **Redis Container**:
    - [ ] Since Redis is running as a container on the same server, ensure the `REDIS_URL` in `docker-compose.yml` uses the service name (`redis`) or localhost inside the same network.
    - [ ] Set `maxmemory` and `maxmemory-policy` in `redis.conf` to prevent the container from consuming all server RAM.
- [ ] **Persistence**:
    - [ ] Mount an AWS EBS volume for `/var/lib/postgresql/data` (if using PG) or the SQLite `.db` file to prevent data loss on container restart.
- [ ] **Health Checks**: Update the Load Balancer (ALB/NLB) to use the `/health` endpoint for readiness/liveness.

## 4. Frontend & API Mapping
- [x] **Dashboard Selection**: Verified `app.js` supports the `?tenant_id=` parameter for customer-specific views.
- [x] **API Status**: Dashboard connectivity logic updated to use `/health` (Legacy `/stats` dependency removed).

## 5. Deployment Commands
> [!IMPORTANT]
> Run these on the destination server:
```bash
# 1. Pull latest changes
git pull origin clean_main

# 2. Build and restart services
docker-compose -p intel up -d --build

# 3. Verify health
curl http://localhost:8000/health
```

## 6. Post-Deployment Verification
- [ ] Access `http://<domain>/docs` and verify the Swagger UI loads.
- [ ] Access `http://<domain>/dashboard/` and verify the "API Online" status.
- [ ] Inject a test log and verify it appears in the logs view.
