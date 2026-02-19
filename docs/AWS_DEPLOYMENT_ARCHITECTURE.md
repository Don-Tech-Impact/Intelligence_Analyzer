# AWS DEPLOYMENT ARCHITECTURE
## Afric Analyzer — Secure, Scalable, Production-Grade

> **Author:** DevOps Architecture Guide  
> **Date:** 2026-02-14  
> **Target:** AWS (eu-west-1 or af-south-1)  
> **Budget Tier:** Startup / Learning → Production  
> **Components:** Repo 1 (Ingestion) · Repo 2 (Intelligence) · Dashboard (React) · Landing Page

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [AWS Service Selection (and WHY)](#2-aws-service-selection-and-why)
3. [Network Architecture (VPC Design)](#3-network-architecture-vpc-design)
4. [Component-by-Component Deployment](#4-component-by-component-deployment)
5. [Security Architecture (Zero-Trust)](#5-security-architecture-zero-trust)
6. [CI/CD Pipeline Design](#6-cicd-pipeline-design)
7. [Monitoring & Observability Stack](#7-monitoring--observability-stack)
8. [Cost Estimation](#8-cost-estimation)
9. [Redis Decision: ElastiCache vs Container](#9-redis-decision-elasticache-vs-container)
10. [DevOps Skills Roadmap](#10-devops-skills-roadmap)
11. [Implementation Phases](#11-implementation-phases)
12. [Key AWS Documentation to Read](#12-key-aws-documentation-to-read)

---

## 1. The Big Picture

```
                         ┌─────────────────────────────────────────┐
                         │         INTERNET / CLIENTS              │
                         │  Firewalls · IDS · Endpoints · Agents   │
                         └───────────┬─────────────┬───────────────┘
                                     │             │
                              HTTPS (Logs)    HTTPS (Users)
                                     │             │
                         ┌───────────▼─────────────▼───────────────┐
                         │       AWS CLOUDFRONT (CDN)               │
                         │   WAF (Web Application Firewall)         │
                         │   ├── api.your-domain.com → ALB (APIs)  │
                         │   ├── app.your-domain.com → S3 (React)  │
                         │   └── www.your-domain.com → S3 (Landing)│
                         └───────────┬─────────────┬───────────────┘
                                     │             │
                    ┌────────────────┘             └────────────────┐
                    │                                               │
           ┌────────▼────────┐                          ┌──────────▼──────────┐
           │ ALB (Application│                          │ S3 Static Hosting   │
           │ Load Balancer)  │                          │ ├── Dashboard (React)│
           │ ├── /api/logs/* │                          │ └── Landing Page    │
           │ │   → Repo 1    │                          └─────────────────────┘
           │ └── /api/v1/*   │
           │     → Repo 2    │
           └────────┬────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───▼───┐     ┌────▼────┐    ┌─────▼─────┐
│ ECS   │     │ ECS     │    │ ECS       │
│ Repo 1│     │ Repo 2  │    │ Repo 2    │
│ API   │────►│ API     │    │ Consumer  │
│       │     │         │    │ Workers   │
└───┬───┘     └────┬────┘    └─────┬─────┘
    │              │               │
    │         ┌────▼───────────────▼────┐
    │         │  PRIVATE SUBNET         │
    └────────►│                         │
              │  ┌──────────────────┐   │
              │  │ ElastiCache Redis│   │
              │  │ (Cluster Mode)   │   │
              │  └──────────────────┘   │
              │                         │
              │  ┌──────────────────┐   │
              │  │ RDS PostgreSQL   │   │
              │  │ (Multi-AZ)       │   │
              │  └──────────────────┘   │
              └─────────────────────────┘
```

### Why This Architecture?

| Principle | How We Achieve It |
|-----------|-------------------|
| **Security** | VPC isolation, private subnets, WAF, encryption at rest + transit, IAM roles, no SSH |
| **Scalability** | ECS auto-scaling, ElastiCache clustering, RDS read replicas, CloudFront CDN |
| **Reliability** | Multi-AZ everything, health checks, automatic failover, blue/green deployments |
| **Observability** | CloudWatch, X-Ray tracing, Container Insights, custom dashboards, PagerDuty alerts |
| **Cost Control** | Right-sized instances, Fargate Spot for consumers, S3 for static hosting, reserved DB |

---

## 2. AWS Service Selection (and WHY)

### Compute: ECS Fargate (NOT EC2, NOT EKS)

| Option | Verdict | Reason |
|--------|---------|--------|
| **EC2 instances** | ❌ Skip | You manage OS patches, scaling, AMIs. Not worth it for containers. |
| **EKS (Kubernetes)** | ❌ Skip for now | Overkill for 4 services. Complex, expensive ($72/mo just for control plane). Learn it later. |
| **ECS Fargate** ✅ | **USE THIS** | Serverless containers. You push a Docker image, AWS runs it. No servers to manage. Auto-scaling built-in. Perfect for learning. |
| **Lambda** | ❌ Skip | Your services are long-running (Redis consumer loops). Lambda is for short tasks. |

**Why Fargate is perfect for you:**
- You already have Dockerfiles ✅
- No server management = focus on application
- Pay per second of compute used
- Scales to zero when idle (cost saving)
- Built-in integration with ALB, CloudWatch, ECR

### Database: RDS PostgreSQL (NOT self-managed)

| Option | Verdict | Reason |
|--------|---------|--------|
| **PostgreSQL in Docker** | ❌ Never in production | Data loss risk. No automated backups. No failover. |
| **RDS PostgreSQL** ✅ | **USE THIS** | Automated backups (35 days), Multi-AZ failover, encryption, monitoring, patching |
| **Aurora PostgreSQL** | ⚡ Future upgrade | 3x faster than RDS, auto-scaling storage. More expensive. Upgrade when traffic demands it. |

### Cache/Queue: ElastiCache Redis (NOT self-managed)

**Answer to your question: YES, use Amazon ElastiCache Redis.** See [Section 9](#9-redis-decision-elasticache-vs-container) for detailed analysis.

| Option | Verdict | Reason |
|--------|---------|--------|
| **Redis in Docker** | ❌ For production | Data loss on restart, no clustering, no encryption, no monitoring |
| **ElastiCache Redis** ✅ | **USE THIS** | Auto-failover, encryption at rest + transit, backup/restore, CloudWatch metrics |
| **Amazon MemoryDB** | ⚡ Future upgrade | Fully durable Redis-compatible. More expensive but zero data loss. |

### Static Hosting: S3 + CloudFront (NOT a server)

| Component | Host On | Why |
|-----------|---------|-----|
| **React Dashboard** | S3 + CloudFront | Static files. No server needed. Global CDN. $0.023/GB. |
| **Landing Page** | S3 + CloudFront | Same. Fast globally. SSL free via ACM. |

### DNS & SSL

| Service | Purpose |
|---------|---------|
| **Route 53** | DNS management for your domain |
| **ACM (Certificate Manager)** | Free SSL/TLS certificates, auto-renewal |
| **CloudFront** | Terminates SSL, global edge locations |

---

## 3. Network Architecture (VPC Design)

This is the **foundation of security**. Everything else builds on this.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        VPC: 10.0.0.0/16                                │
│                        (65,536 IP addresses)                           │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  AVAILABILITY ZONE A (eu-west-1a)                               │   │
│   │                                                                   │   │
│   │  ┌─────────────────────┐  ┌──────────────────────────────────┐  │   │
│   │  │ PUBLIC SUBNET       │  │ PRIVATE SUBNET                    │  │   │
│   │  │ 10.0.1.0/24         │  │ 10.0.10.0/24                     │  │   │
│   │  │                     │  │                                    │  │   │
│   │  │ • ALB               │  │ • ECS Fargate (Repo 1 API)       │  │   │
│   │  │ • NAT Gateway       │  │ • ECS Fargate (Repo 2 API)       │  │   │
│   │  │                     │  │ • ECS Fargate (Repo 2 Consumer)  │  │   │
│   │  │                     │  │                                    │  │   │
│   │  └─────────────────────┘  └──────────────────────────────────┘  │   │
│   │                                                                   │   │
│   │                           ┌──────────────────────────────────┐  │   │
│   │                           │ ISOLATED SUBNET (DATA)           │  │   │
│   │                           │ 10.0.20.0/24                     │  │   │
│   │                           │                                    │  │   │
│   │                           │ • RDS PostgreSQL (Primary)       │  │   │
│   │                           │ • ElastiCache Redis (Primary)    │  │   │
│   │                           └──────────────────────────────────┘  │   │
│   └───────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  AVAILABILITY ZONE B (eu-west-1b)                               │   │
│   │                                                                   │   │
│   │  ┌─────────────────────┐  ┌──────────────────────────────────┐  │   │
│   │  │ PUBLIC SUBNET       │  │ PRIVATE SUBNET                    │  │   │
│   │  │ 10.0.2.0/24         │  │ 10.0.11.0/24                     │  │   │
│   │  │                     │  │                                    │  │   │
│   │  │ • ALB (standby)     │  │ • ECS Fargate (replicas)         │  │   │
│   │  │ • NAT Gateway       │  │                                    │  │   │
│   │  │   (redundancy)      │  │                                    │  │   │
│   │  └─────────────────────┘  └──────────────────────────────────┘  │   │
│   │                                                                   │   │
│   │                           ┌──────────────────────────────────┐  │   │
│   │                           │ ISOLATED SUBNET (DATA)           │  │   │
│   │                           │ 10.0.21.0/24                     │  │   │
│   │                           │                                    │  │   │
│   │                           │ • RDS PostgreSQL (Standby)       │  │   │
│   │                           │ • ElastiCache Redis (Replica)    │  │   │
│   │                           └──────────────────────────────────┘  │   │
│   └───────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Subnet Strategy

| Subnet Type | CIDR | Accessible From | Contains |
|-------------|------|----------------|----------|
| **Public** | `10.0.1.0/24`, `10.0.2.0/24` | Internet (via IGW) | ALB, NAT Gateway only |
| **Private** | `10.0.10.0/24`, `10.0.11.0/24` | Public subnet only (via ALB) | ECS tasks (all application code) |
| **Isolated (Data)** | `10.0.20.0/24`, `10.0.21.0/24` | Private subnet only | RDS, ElastiCache (NO internet access) |

### Key Rule: **Application code NEVER touches the internet directly.**
- Outbound traffic (e.g., threat intel feeds) goes through NAT Gateway
- Inbound traffic goes through ALB → private subnet
- Database is in isolated subnet — no internet route at all

### Security Groups (Firewalls)

```
SG-ALB:
  Inbound:  443 from 0.0.0.0/0 (HTTPS only, no HTTP)
  Outbound: 8000,8080 to SG-ECS

SG-ECS:
  Inbound:  8000,8080 from SG-ALB only
  Outbound: 6379 to SG-Redis
             5432 to SG-RDS
             443 to 0.0.0.0/0 (for threat intel feeds, via NAT)

SG-Redis:
  Inbound:  6379 from SG-ECS only
  Outbound: None

SG-RDS:
  Inbound:  5432 from SG-ECS only
  Outbound: None
```

**This means:** Even if an attacker compromises your application container, they cannot reach the database directly — only traffic from the ECS security group is allowed.

---

## 4. Component-by-Component Deployment

### 4.1 Repo 1 — Log Ingestion API (ECS Fargate)

```yaml
# ECS Task Definition (conceptual)
Service: repo1-api
Image: <account>.dkr.ecr.<region>.amazonaws.com/repo1:latest
Port: 8080
CPU: 512 (0.5 vCPU)
Memory: 1024 MB
DesiredCount: 2  # Minimum for HA
AutoScaling:
  Min: 2
  Max: 10
  MetricType: ECSServiceAverageCPUUtilization
  TargetValue: 70
HealthCheck:
  Path: /health
  Interval: 30s
  Timeout: 5s
Environment:
  REDIS_URL: redis://your-elasticache-endpoint:6379/0
  # NO database URL needed — Repo 1 only writes to Redis
```

**ALB Routing Rule:**
```
Host: api.your-domain.com
Path: /api/logs/*  →  Target Group: repo1-tg (port 8080)
Path: /admin/*     →  Target Group: repo1-tg (port 8080)
```

**Why 2 minimum tasks?**
- One goes down during deployment → other handles traffic
- Multi-AZ resilience — tasks spread across AZ-A and AZ-B

### 4.2 Repo 2 — Intelligence Analyzer API (ECS Fargate)

```yaml
Service: repo2-api
Image: <account>.dkr.ecr.<region>.amazonaws.com/repo2:latest
Port: 8000
CPU: 512
Memory: 1024 MB
DesiredCount: 2
AutoScaling:
  Min: 2
  Max: 8
  MetricType: ECSServiceAverageCPUUtilization
  TargetValue: 70
HealthCheck:
  Path: /health/live
  Interval: 30s
Command: ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
Environment:
  DATABASE_URL: postgresql://user:pass@rds-endpoint:5432/siem_db
  REDIS_URL: redis://elasticache-endpoint:6379/0
  SECRET_KEY: <from-AWS-Secrets-Manager>
```

**ALB Routing Rule:**
```
Host: api.your-domain.com
Path: /api/v1/*    →  Target Group: repo2-tg (port 8000)
Path: /stats       →  Target Group: repo2-tg (port 8000)
Path: /alerts      →  Target Group: repo2-tg (port 8000)
Path: /health/*    →  Target Group: repo2-tg (port 8000)
```

### 4.3 Repo 2 — Consumer Workers (ECS Fargate)

```yaml
Service: repo2-consumer
Image: <account>.dkr.ecr.<region>.amazonaws.com/repo2:latest
Port: None (no inbound traffic)
CPU: 256
Memory: 512 MB
DesiredCount: 2
AutoScaling:
  Min: 2
  Max: 20  # Scale aggressively for log spikes
  MetricType: Custom (Redis queue depth)
  # Scale up when: logs:default:clean queue > 1000
  # Scale down when: queue < 100
Command: ["python", "-m", "src.services.redis_consumer"]
CapacityProvider: FARGATE_SPOT  # 70% cheaper! Consumer is fault-tolerant.
Environment:
  DATABASE_URL: postgresql://...
  REDIS_URL: redis://...
  BATCH_SIZE: 100
  BATCH_TIMEOUT_MS: 1000
```

**Why FARGATE_SPOT for consumers?**
- Consumers are **stateless** — if one dies, another picks up
- Redis queue guarantees no message loss (BRPOP is atomic)
- Spot pricing = 50-70% cheaper than on-demand
- Perfect use case for interruptible workloads

### 4.4 React Dashboard (S3 + CloudFront)

```
Build: npm run build → produces /build directory
Upload: aws s3 sync build/ s3://your-dashboard-bucket/
CloudFront: Distribution pointing to S3 bucket
Domain: app.your-domain.com → CloudFront

CloudFront Config:
  - Origin: S3 bucket (OAC - Origin Access Control)
  - Error Pages: 403, 404 → /index.html (React SPA routing)
  - Cache Policy: CachingOptimized (1 day, Gzip/Brotli)
  - SSL: ACM certificate (free)
  - WAF: Attached (rate limiting, bot protection)
```

**The dashboard `API_BASE_URL` should point to:**
```javascript
const API_BASE_URL = 'https://api.your-domain.com';  // ALB endpoint
```

### 4.5 Landing Page (S3 + CloudFront)

Same pattern as the dashboard but separate bucket:
```
Domain: www.your-domain.com → CloudFront → S3 bucket
your-domain.com → redirect to www.your-domain.com
```

### DNS Layout (Route 53)

| Record | Type | Target |
|--------|------|--------|
| `your-domain.com` | A (Alias) | CloudFront (redirect to www) |
| `www.your-domain.com` | A (Alias) | CloudFront (landing page) |
| `app.your-domain.com` | A (Alias) | CloudFront (React dashboard) |
| `api.your-domain.com` | A (Alias) | ALB (APIs) |

---

## 5. Security Architecture (Zero-Trust)

### 5.1 The 7 Layers of Security

```
Layer 1: CloudFront + WAF        ← DDoS protection, bot filtering, rate limiting
Layer 2: ALB + SSL Termination   ← HTTPS only, certificate validation
Layer 3: Security Groups         ← Network firewall (port-level isolation)
Layer 4: IAM Roles               ← No hardcoded credentials, least privilege
Layer 5: Secrets Manager         ← Encrypted secrets, automatic rotation
Layer 6: Encryption at Rest      ← RDS, ElastiCache, S3 all AES-256
Layer 7: Application Auth        ← JWT + RLS (your existing code)
```

### 5.2 WAF Rules (Web Application Firewall)

```
Rule 1: Rate Limiting
  - 2000 requests/5 min per IP (API endpoints)
  - Block for 5 minutes on exceed

Rule 2: AWS Managed Rules
  - AWSManagedRulesCommonRuleSet (SQLi, XSS, SSRF protection)
  - AWSManagedRulesKnownBadInputsRuleSet (Log4j, etc.)
  - AWSManagedRulesAmazonIpReputationList (known bad IPs)

Rule 3: GeoBlocking (optional)
  - Allow only expected countries
  - Block known-bad geolocations

Rule 4: Bot Control
  - Block common bot user agents
  - CAPTCHA challenge for suspicious patterns
```

### 5.3 Secrets Management

**NEVER put secrets in code, env files, or Docker images.**

```
AWS Secrets Manager:
  ├── /siem/prod/database-url          → PostgreSQL connection string
  ├── /siem/prod/redis-url             → ElastiCache connection string
  ├── /siem/prod/jwt-secret            → JWT signing key (auto-rotate 90 days)
  ├── /siem/prod/smtp-credentials      → Email service credentials
  └── /siem/prod/repo1-api-keys        → API keys for log ingestion

ECS tasks load secrets at startup via:
  secrets:
    - name: DATABASE_URL
      valueFrom: arn:aws:secretsmanager:<region>:<account>:secret:/siem/prod/database-url
    - name: SECRET_KEY
      valueFrom: arn:aws:secretsmanager:<region>:<account>:secret:/siem/prod/jwt-secret
```

### 5.4 IAM Roles (Least Privilege)

```
Role: ECSTaskRole-Repo1
  Permissions:
    - elasticache:Connect (Redis only)
    - logs:CreateLogStream, logs:PutLogEvents (CloudWatch)
    - secretsmanager:GetSecretValue (only /siem/prod/redis-url)

Role: ECSTaskRole-Repo2
  Permissions:
    - elasticache:Connect
    - rds-db:connect
    - logs:CreateLogStream, logs:PutLogEvents
    - secretsmanager:GetSecretValue (only /siem/prod/*)
    - s3:PutObject (reports bucket only)

Role: ECSTaskRole-Consumer
  Same as Repo2 but NO s3:PutObject

Role: GitHubActionsRole (for CI/CD)
  Permissions:
    - ecr:PushImage
    - ecs:UpdateService
    - ecs:RegisterTaskDefinition
```

### 5.5 Encryption Everywhere

| Component | At Rest | In Transit |
|-----------|---------|------------|
| RDS PostgreSQL | ✅ AES-256 (KMS) | ✅ TLS 1.2 required |
| ElastiCache Redis | ✅ AES-256 (KMS) | ✅ TLS 1.2 + AUTH token |
| S3 Buckets | ✅ SSE-S3 | ✅ HTTPS only (bucket policy) |
| ECR Images | ✅ AES-256 | ✅ HTTPS |
| ALB Traffic | N/A | ✅ TLS 1.2 (ACM cert) |
| ECS Task ↔ Redis | N/A | ✅ in-transit encryption |

---

## 6. CI/CD Pipeline Design

### Architecture: GitHub Actions → AWS

```
Developer pushes to main
         │
         ▼
┌─────────────────────────────────────────────────┐
│  GitHub Actions Pipeline                         │
│                                                   │
│  Stage 1: LINT & SECURITY                        │
│  ├── flake8 (code quality)                       │
│  ├── bandit (security scan)                      │
│  ├── trivy (Docker image vulnerability scan)     │
│  └── checkov (IaC security scan)                 │
│                                                   │
│  Stage 2: TEST                                    │
│  ├── pytest with coverage (unit + integration)   │
│  ├── API contract tests                          │
│  └── Coverage report → Codecov                   │
│                                                   │
│  Stage 3: BUILD & PUSH                           │
│  ├── docker build --target production            │
│  ├── trivy scan on built image                   │
│  ├── docker tag :latest, :<sha>, :<timestamp>    │
│  └── docker push → ECR                           │
│                                                   │
│  Stage 4: DEPLOY (Staging)                       │
│  ├── Update ECS task definition (new image)      │
│  ├── ECS rolling update (blue/green)             │
│  ├── Wait for healthy targets                    │
│  └── Run smoke tests against staging             │
│                                                   │
│  Stage 5: DEPLOY (Production)                    │
│  ├── Manual approval gate ← (you click "approve")│
│  ├── Update ECS task definition                  │
│  ├── ECS rolling update                          │
│  ├── Wait for healthy targets                    │
│  └── Run production smoke tests                  │
│                                                   │
│  Stage 6: NOTIFY                                 │
│  └── Slack/Discord notification (success/fail)   │
└─────────────────────────────────────────────────┘
```

### GitHub Actions Workflow (Key Concepts)

```yaml
# .github/workflows/deploy.yml (conceptual)
name: Deploy to AWS

on:
  push:
    branches: [main]

permissions:
  id-token: write  # For OIDC auth to AWS (no access keys!)
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # Authenticate to AWS using OIDC (NO secret keys stored!)
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<account>:role/GitHubActionsRole
          aws-region: eu-west-1

      # Login to ECR
      - uses: aws-actions/amazon-ecr-login@v2

      # Build and push
      - run: |
          docker build -t $ECR_REPO:$GITHUB_SHA .
          docker push $ECR_REPO:$GITHUB_SHA

      # Update ECS service (rolling deploy)
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: task-def.json
          service: repo2-api
          cluster: siem-cluster
          wait-for-service-stability: true
```

### Key DevOps Concept: OIDC Authentication (No Access Keys!)

Instead of storing AWS access keys as GitHub secrets (risky), you use **OpenID Connect (OIDC)**:
1. AWS trusts GitHub as an identity provider
2. GitHub Actions gets a temporary token (15 min)
3. Token is scoped to specific permissions
4. No long-lived credentials ever exist

**This is the #1 DevOps security skill to learn.**

---

## 7. Monitoring & Observability Stack

### The 3 Pillars

```
┌────────────────────────────────────────────────────┐
│                 OBSERVABILITY                       │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │  METRICS  │  │   LOGS   │  │     TRACES       │ │
│  │           │  │          │  │                    │ │
│  │ CloudWatch│  │CloudWatch│  │  AWS X-Ray        │ │
│  │ Container │  │ Logs     │  │  (optional)       │ │
│  │ Insights  │  │          │  │                    │ │
│  │           │  │ Centralized│ │  Request → Redis │ │
│  │ CPU, Mem, │  │ JSON logs│  │  → DB → Response │ │
│  │ Network,  │  │ from all │  │  with timing     │ │
│  │ Queue     │  │ services │  │                    │ │
│  │ depth     │  │          │  │                    │ │
│  └──────────┘  └──────────┘  └──────────────────┘ │
│                                                     │
│           ┌──────────────────────┐                  │
│           │    ALERTING          │                  │
│           │                      │                  │
│           │  CloudWatch Alarms   │                  │
│           │  → SNS → Email/Slack │                  │
│           │  → PagerDuty         │                  │
│           └──────────────────────┘                  │
└────────────────────────────────────────────────────┘
```

### CloudWatch Dashboards to Build

**Dashboard 1: Infrastructure Health**
```
┌──────────────────┬──────────────────┬──────────────────┐
│ ECS CPU Usage    │ ECS Memory Usage │ Active Tasks     │
│ (all services)   │ (all services)   │ (per service)    │
├──────────────────┼──────────────────┼──────────────────┤
│ ALB Request Count│ ALB Error Rate   │ ALB Latency P99  │
│ (per target grp) │ (4xx, 5xx)       │ (< 500ms target) │
├──────────────────┼──────────────────┼──────────────────┤
│ RDS CPU          │ RDS Connections  │ RDS IOPS         │
│ (< 80% target)   │ (< 180 target)  │ (read/write)     │
├──────────────────┼──────────────────┼──────────────────┤
│ Redis CPU        │ Redis Memory     │ Redis Evictions  │
│ (< 70% target)   │ (< 80% target)  │ (should be 0)    │
└──────────────────┴──────────────────┴──────────────────┘
```

**Dashboard 2: Application Health**
```
┌──────────────────┬──────────────────┬──────────────────┐
│ Logs Ingested    │ Logs Processed   │ Queue Depth      │
│ (/min)           │ (/min)           │ (clean queue)    │
├──────────────────┼──────────────────┼──────────────────┤
│ Alerts Generated │ Dead Letters     │ Processing       │
│ (by severity)    │ (/hour, < 1%)   │ Latency (ms)     │
├──────────────────┼──────────────────┼──────────────────┤
│ API Response Time│ API Error Rate   │ Active Tenants   │
│ (P50, P95, P99)  │ (< 1% target)   │                  │
└──────────────────┴──────────────────┴──────────────────┘
```

### Critical Alarms

| Alarm | Condition | Action |
|-------|-----------|--------|
| **High CPU** | ECS CPU > 80% for 5 min | Auto-scale + notify |
| **High Memory** | ECS Memory > 85% for 5 min | Auto-scale + notify |
| **Queue Backup** | Redis queue > 5000 for 10 min | Scale consumers + **page on-call** |
| **High Error Rate** | ALB 5xx > 5% for 3 min | **Page on-call immediately** |
| **DB Connection Exhaustion** | RDS connections > 180 for 5 min | Investigate + notify |
| **Redis Memory** | Memory > 80% | Scale up + notify |
| **Dead Letter Spike** | Dead letters > 100/hour | Notify — possible schema mismatch |
| **Zero Throughput** | 0 logs processed for 15 min | **Page on-call** — pipeline may be down |
| **SSL Certificate Expiry** | ACM cert < 30 days | Notify (should auto-renew) |

### Custom Metric: Redis Queue Depth

Your consumer already has metrics. Publish them to CloudWatch:

```python
# In redis_consumer.py, add:
import boto3
cloudwatch = boto3.client('cloudwatch')

def publish_queue_metrics():
    queue_depth = redis_client.llen('logs:default:clean')
    cloudwatch.put_metric_data(
        Namespace='SIEM/Application',
        MetricData=[{
            'MetricName': 'QueueDepth',
            'Value': queue_depth,
            'Unit': 'Count',
            'Dimensions': [
                {'Name': 'QueueName', 'Value': 'clean'},
                {'Name': 'TenantId', 'Value': 'default'}
            ]
        }]
    )
```

---

## 8. Cost Estimation

### Starter Tier (Learning / Development)

| Service | Size | Monthly Cost |
|---------|------|-------------|
| ECS Fargate (Repo 1, 2 tasks) | 0.5 vCPU, 1 GB | ~$30 |
| ECS Fargate (Repo 2 API, 2 tasks) | 0.5 vCPU, 1 GB | ~$30 |
| ECS Fargate (Consumers, 2 tasks SPOT) | 0.25 vCPU, 0.5 GB | ~$8 |
| RDS PostgreSQL (Single-AZ) | db.t3.micro | ~$15 |
| ElastiCache Redis (Single node) | cache.t3.micro | ~$13 |
| ALB | 1 ALB | ~$22 |
| S3 (Dashboard + Landing) | < 1 GB | ~$0.03 |
| CloudFront (CDN) | < 10 GB/month | ~$1 |
| Route 53 (DNS) | 1 hosted zone | ~$0.50 |
| ECR (Container Registry) | < 5 GB | ~$0.50 |
| CloudWatch (Logs + Metrics) | Basic | ~$10 |
| NAT Gateway | 1 (shared) | ~$33 |
| **Total** | | **~$163/month** |

### Production Tier (Multi-AZ, HA)

| Service | Size | Monthly Cost |
|---------|------|-------------|
| ECS Fargate (all services, scaled) | Multiple tasks | ~$150 |
| RDS PostgreSQL (Multi-AZ) | db.t3.medium | ~$70 |
| ElastiCache Redis (Multi-AZ) | cache.t3.small | ~$50 |
| ALB + WAF | 1 ALB + WAF | ~$40 |
| NAT Gateways (2, one per AZ) | 2 | ~$66 |
| CloudWatch + Alarms | Higher tier | ~$30 |
| Secrets Manager | 5 secrets | ~$2 |
| Everything else | S3, CF, Route53, ECR | ~$10 |
| **Total** | | **~$418/month** |

### Cost Saving Tips

| Tip | Savings |
|-----|---------|
| Use **Fargate Spot** for consumers | 50-70% on consumer cost |
| Use **RDS Reserved Instance** (1yr) | 30-40% on RDS |
| Use **VPC Endpoints** for ECR, S3, CloudWatch | Avoid NAT Gateway data charges |
| Start Single-AZ, move to Multi-AZ when ready | Save ~50% on RDS/Redis |
| Use **S3 Intelligent Tiering** for reports | Automatic cost optimization |

---

## 9. Redis Decision: ElastiCache vs Container

### Short Answer: **Use ElastiCache for production. Keep Docker Redis for local dev.**

### Detailed Comparison

| Feature | Docker Redis (container) | ElastiCache Redis |
|---------|--------------------------|-------------------|
| **Setup** | 5 minutes | 30 minutes |
| **Cost** | $0 (runs on your instance) | ~$13-50/month |
| **Persistence** | Volume mount (risky) | Automatic snapshots (daily) |
| **Failover** | Manual | Automatic (Multi-AZ, < 15s) |
| **Encryption at rest** | ❌ No | ✅ AES-256 (KMS) |
| **Encryption in transit** | ❌ No (unless you set up TLS manually) | ✅ TLS 1.2 built-in |
| **Monitoring** | None (you build it) | CloudWatch metrics (20+ metrics) |
| **Scaling** | Stop → resize → start | Online scaling (no downtime) |
| **Patching** | You do it | AWS does it (maintenance window) |
| **Backups** | Manual | Automatic daily + on-demand |
| **Auth** | Optional password | AUTH token + IAM auth |
| **SLA** | None | 99.99% |

### What Happens to Your Code?

**Nothing changes.** The only difference is the connection URL:

```python
# Local development (Docker Redis)
REDIS_URL=redis://localhost:6379/0

# AWS ElastiCache (TLS enabled)
REDIS_URL=rediss://your-cluster.cache.amazonaws.com:6379/0
#        ^^ note the extra 's' for TLS
```

Your `src/core/config.py` already reads `REDIS_URL` from environment. Zero code changes.

### Local Dev Workflow

```yaml
# docker-compose.local.yml (for development)
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

# Production: use ElastiCache endpoint in environment variables
```

---

## 10. DevOps Skills Roadmap

### What This Project Teaches You

```
Level 1: CONTAINERIZATION (You're here ✅)
  ✅ Dockerfile (multi-stage builds)
  ✅ docker-compose (multi-service orchestration)
  ✅ Container networking
  ✅ Volume management

Level 2: CLOUD INFRASTRUCTURE (Next step 👈)
  □ VPC design (subnets, routing, security groups)
  □ ECS Fargate (serverless containers)
  □ RDS (managed databases)
  □ ElastiCache (managed Redis)
  □ ALB (load balancing, path-based routing)
  □ S3 + CloudFront (static hosting)

Level 3: SECURITY & IAM
  □ IAM roles and policies (least privilege)
  □ Secrets Manager (no hardcoded credentials)
  □ WAF (web application firewall)
  □ OIDC authentication (GitHub → AWS, no access keys)
  □ VPC security groups (network isolation)
  □ Encryption (at rest + in transit)

Level 4: CI/CD
  □ GitHub Actions advanced workflows
  □ ECR (container registry)
  □ Blue/Green deployments
  □ Manual approval gates
  □ Environment promotion (staging → production)
  □ Infrastructure as Code (Terraform or CloudFormation)

Level 5: OBSERVABILITY
  □ CloudWatch metrics, logs, alarms
  □ Container Insights
  □ Custom metrics (queue depth, processing latency)
  □ Dashboards that tell a story
  □ Alerting and on-call setup

Level 6: INFRASTRUCTURE AS CODE (Advanced)
  □ Terraform (define everything in code)
  □ State management (S3 backend, DynamoDB locking)
  □ Modules and reusable components
  □ Drift detection

Level 7: KUBERNETES (Future goal)
  □ EKS (managed Kubernetes)
  □ Helm charts
  □ Service mesh (Istio)
  □ GitOps (ArgoCD/FluxCD)
```

### Recommended Learning Sequence (with this project)

| Week | Focus | What to Build |
|------|-------|---------------|
| **Week 1** | AWS Basics | Create VPC manually in Console. Understand subnets, IGW, NAT, SGs. Deploy 1 EC2 instance. |
| **Week 2** | ECR + ECS | Push your Docker image to ECR. Create ECS cluster. Run Repo 2 API on Fargate. |
| **Week 3** | RDS + ElastiCache | Create RDS PostgreSQL. Create ElastiCache Redis. Connect Repo 2 to both. |
| **Week 4** | ALB + Routing | Create ALB. Set up path-based routing. Point HTTPS traffic to ECS tasks. |
| **Week 5** | S3 + CloudFront | Deploy React dashboard to S3. Set up CloudFront. Custom domain + SSL. |
| **Week 6** | CI/CD | Set up GitHub Actions → ECR → ECS pipeline. OIDC auth. Automated deployments. |
| **Week 7** | Security Hardening | Secrets Manager, WAF, IAM roles, encryption. Run security scan. |
| **Week 8** | Monitoring | CloudWatch dashboards, alarms, custom metrics. Set up alerting (Slack/email). |
| **Week 9** | Terraform | Rewrite everything in Terraform. Destroy and recreate from code. |
| **Week 10** | Production Polish | Multi-AZ, auto-scaling policies, load testing, disaster recovery drill. |

---

## 11. Implementation Phases

### Phase 1: Foundation (Week 1-2)

```
□ Create AWS account (use IAM Identity Center, NOT root account)
□ Set up billing alerts ($50/month, $100/month, $200/month)
□ Create VPC with public + private + isolated subnets (2 AZs)
□ Create ECR repositories (repo1, repo2)
□ Push Docker images to ECR
□ Create ECS cluster (Fargate)
□ Deploy Repo 2 API as ECS service (test with SQLite first)
```

### Phase 2: Data Layer (Week 3)

```
□ Create RDS PostgreSQL (start with db.t3.micro, Single-AZ)
□ Run init_db.sql on RDS
□ Create ElastiCache Redis (cache.t3.micro, Single node)
□ Update ECS task definitions with RDS + ElastiCache endpoints
□ Test: push logs to Redis, verify consumer processes them
```

### Phase 3: Networking & Security (Week 4-5)

```
□ Create ALB in public subnet
□ Configure path-based routing (Repo 1 vs Repo 2)
□ Set up Route 53 hosted zone
□ Create ACM certificate (api.domain.com, app.domain.com, www.domain.com)
□ Deploy React dashboard to S3 + CloudFront
□ Deploy landing page to S3 + CloudFront
□ Test end-to-end: device → Repo 1 → Redis → Repo 2 → Dashboard
```

### Phase 4: CI/CD + Monitoring (Week 6-8)

```
□ Set up OIDC auth (GitHub → AWS)
□ Create GitHub Actions deploy workflow
□ Set up CloudWatch Container Insights
□ Create 2 CloudWatch dashboards (infra + app)
□ Create critical alarms (5+)
□ Set up SNS → email notifications
□ Move secrets to Secrets Manager
□ Enable WAF on CloudFront and ALB
```

### Phase 5: Production Hardening (Week 9-10)

```
□ Enable Multi-AZ on RDS
□ Enable Multi-AZ on ElastiCache
□ Set up auto-scaling policies (CPU + queue-based)
□ Run load test (scripts/load_test.py adapted for AWS)
□ Terraform everything (IaC)
□ Disaster recovery drill: kill a service, verify auto-recovery
□ Document runbooks and procedures
```

---

## 12. Key AWS Documentation to Read

### Must-Read (In Order)

| # | Topic | AWS Doc | Why |
|---|-------|---------|-----|
| 1 | **VPC Basics** | [VPC User Guide](https://docs.aws.amazon.com/vpc/latest/userguide/) | Network foundation |
| 2 | **ECS on Fargate** | [ECS Developer Guide](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html) | Where your containers run |
| 3 | **ECR** | [ECR User Guide](https://docs.aws.amazon.com/AmazonECR/latest/userguide/) | Container registry |
| 4 | **ALB** | [ELB User Guide](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/) | Load balancing |
| 5 | **RDS PostgreSQL** | [RDS User Guide](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/) | Managed database |
| 6 | **ElastiCache Redis** | [ElastiCache User Guide](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/) | Managed Redis |
| 7 | **S3 Static Hosting** | [S3 Static Website](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html) | Dashboard hosting |
| 8 | **CloudFront** | [CloudFront Developer Guide](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/) | CDN + SSL |
| 9 | **IAM Best Practices** | [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) | Security foundation |
| 10 | **Secrets Manager** | [Secrets Manager User Guide](https://docs.aws.amazon.com/secretsmanager/latest/userguide/) | Secret storage |

### Recommended Free Courses

| Course | Platform | Duration |
|--------|----------|----------|
| AWS Cloud Practitioner Essentials | [AWS Skill Builder](https://explore.skillbuilder.aws) | 6 hours |
| Docker Deep Dive | YouTube (TechWorld with Nana) | 3 hours |
| GitHub Actions CI/CD | [GitHub Skills](https://skills.github.com) | 2 hours |
| Terraform Getting Started | [HashiCorp Learn](https://developer.hashicorp.com/terraform/tutorials) | 4 hours |

### Tools to Install

| Tool | Purpose | Install |
|------|---------|---------|
| **AWS CLI v2** | Manage AWS from terminal | `msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi` |
| **Session Manager Plugin** | SSH into ECS tasks (no bastion needed!) | AWS docs |
| **Terraform** | Infrastructure as Code | `choco install terraform` |
| **aws-vault** | Secure AWS credential management locally | `choco install aws-vault` |

---

## Quick Reference Card

```
YOUR PRODUCTION URLS:
  Landing Page:    https://www.your-domain.com     → S3 + CloudFront
  Dashboard:       https://app.your-domain.com     → S3 + CloudFront
  API (Repo 1):    https://api.your-domain.com/api/logs/*  → ALB → ECS
  API (Repo 2):    https://api.your-domain.com/api/v1/*    → ALB → ECS
  Health Check:    https://api.your-domain.com/health       → ALB → ECS

DATA FLOW:
  Device → Repo 1 (port 8080) → Redis → Repo 2 Consumer → PostgreSQL
                                           ↓
  Dashboard ← Repo 2 API (port 8000) ← Alerts/Reports

SCALING:
  Repo 1 API:     2-10 tasks (CPU-based auto-scale)
  Repo 2 API:     2-8 tasks  (CPU-based auto-scale)
  Repo 2 Consumer: 2-20 tasks (Queue-depth auto-scale, SPOT pricing)

SECURITY CHECKLIST:
  ✅ All traffic is HTTPS (ACM certs)
  ✅ No public access to database or Redis
  ✅ Secrets in AWS Secrets Manager
  ✅ IAM roles (no access keys in code)
  ✅ WAF on CloudFront + ALB
  ✅ Security groups (port-level isolation)
  ✅ Encryption at rest + in transit
  ✅ OIDC for CI/CD (no long-lived credentials)
```
