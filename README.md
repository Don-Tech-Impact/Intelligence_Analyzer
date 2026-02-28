# 🛡️ Intelligence SIEM Analyzer - Production V1.0

A professional-grade Security Information and Event Management (SIEM) system designed for multi-tenant business environments. Featuring intelligent normalization, real-time threat detection, and business-focused security analytics.

## 🚀 Version 1.0 Production Deliverables

### 📡 Core Backend Features
- **Multi-Vendor Ingestion**: Unified normalization logic for **pfSense**, **Ubiquiti**, **Cisco**, and Syslog.
- **Dynamic JWT Authentication**: Secure RBAC with Repo 1 synchronization via Redis-backed secret fallback.
- **Tenant Isolation**: Strict data segregation ensuring businesses only see logs/alerts belonging to their `tenant_id`.
- **Automated Reporting**: Daily/Weekly generation of professional security summaries.
- **Notification Suite**: Real-time alerts via Email and Webhooks (Slack/Discord).

### 📊 Dashboard & Monitoring
- **Premium UI**: Glassmorphic dark mode dashboard with high-density security data visualization.
- **Threat Activity Timeline**: Real-time telemetry monitoring and anomalous traffic pattern detection.
- **Business Insights**: Analytics designed for strategy, including Business Hour vs. After Hour patterns.
- **System Health**: Active monitoring of CPU, RAM, and database integrity.

## 🛠️ Technical Architecture
- **API Framework**: Python 3.11+, FastAPI (Asynchronous execution).
- **Orchestration**: Docker & Docker Compose (Zero-Config deployment).
- **Database**: PostgreSQL (High-performance persistent storage).
- **Data Pipeline**: Redis (High-throughput message queue).
- **Auth Layer**: RSA/HS256 JWT with strict claims verification.

## 🏗️ Project Structure
- `/src/api`: FastAPI endpoints and security dependencies.
- `/src/models`: SQLAlchemy database schemas and validation.
- `/src/services`: Core logic (Ingestion, Normalization, Analytics).
- `/dashboard`: Premium glassmorphic frontend assets.
- `/scripts`: Database initialization and system utilities.

## 🚦 Getting Started (Production)

### 1. Environment Configuration
Create or update your `.env` file in the root directory:
```bash
SECRET_KEY=your_shared_repo1_secret
ADMIN_KEY=your_internal_service_key
DATABASE_URL=postgresql://admin:password@siem-db:5432/siem_analyzer
REDIS_URL=redis://siem-redis:6379/0
```

### 2. Deployment
The entire system is containerized for stability:
```bash
docker-compose up -d
```

### 3. Verification
Access the system overview at: `http://localhost:8000/api/admin/system/overview` (Requires `X-Admin-Key` header).
Access the dashboard at: `http://localhost:8000/dashboard/`

---
*Developed for Don-Tech-Impact. Confidential & Proprietary.*
