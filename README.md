# 🛡️ Intelligence SIEM Analyzer - Production V1.1

A professional-grade Security Information and Event Management (SIEM) system designed for multi-tenant business environments. Intelligent normalization, real-time threat detection, and business-focused analytics.

## 🚀 Version 1.1 Deliverables

### 📡 Core Backend Features
- **Multi-Vendor Ingestion**: Unified normalization logic for **pfSense**, **Ubiquiti**, **Cisco**, and generic Syslog.
- **JWT Authentication**: Secure RBAC (Role-Based Access Control) with `superadmin` and `business` user roles.
- **Tenant Isolation**: Strict data segregation ensuring businesses only see logs/alerts belonging to their `tenant_id`.
- **Automated Reporting**: Daily/Weekly generation of CSV and HTML security summaries.
- **Notification Suite**: Real-time alerts via Email and Webhooks (Slack/Discord).

### 📊 Dashboard & Monitoring
- **Cinematic UI**: Glassmorphic dark mode dashboard with high-density data visualization.
- **Live Stream**: Real-time telemetry console for incoming endpoint logs.
- **Business Insights**: Analytics designed for strategy, including Business Hour vs. After Hour patterns and Weekend traffic analysis.
- **System Health**: Active monitoring of CPU, RAM, and database integrity.

## 🛠️ Technology Stack
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy.
- **Data Pipeline**: Redis (Message Queue), SQLite (Production-ready V1 storage).
- **Security**: PBKDF2 Hashing, JWT (JOSE), HMAC log signing.
- **Frontend**: Vanilla JS (V1.1), optimized for future **React** migration.

## 🏗️ Folder Structure
- `/src/api`: FastAPI endpoints and security dependencies.
- `/src/models`: SQLAlchemy database schemas.
- `/src/services`: Core logic (Ingestion, Normalization, Reporting).
- `/src/utils`: Auth helpers and security utilities.
- `/dashboard`: Premium frontend assets.
- `/scripts`: System monitoring and backup tools.
- `/reports`: Archive for generated security documents.

## 🚦 Getting Started

### 1. Installation
```powershell
pip install -r requirements.txt
```

### 2. Configuration
Update `config/config.yaml` with your SMTP and Webhook credentials. Set your environment variable:
`$env:SECRET_KEY = "your-very-secure-key"`

### 3. Run the Analyzer
```powershell
python -m src.main
```
Access the dashboard at: `http://localhost:8000/dashboard/login.html`

## 🔒 Default Credentials (Change on First Login)
- **User**: `admin`
- **Pass**: `admin123`

---
*Developed for Don-Tech-Impact. Confidential & Proprietary.*
