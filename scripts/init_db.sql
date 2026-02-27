-- =============================================================================
-- INTELLIGENCE ANALYZER - DATABASE INITIALIZATION
-- =============================================================================
-- This script runs on PostgreSQL container startup
-- Creates: Partitioned logs table, dead_letters, indexes, RLS policies
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================================================
-- LOGS TABLE (Time-Partitioned)
-- =============================================================================
-- Partitioning Strategy: Monthly partitions
-- Why: 
--   1. Efficient data lifecycle (DROP PARTITION vs DELETE WHERE)
--   2. Query pruning for time-range queries (common in SIEM)
--   3. Manageable partition count (12/year vs 1000s for tenant-based)
-- =============================================================================

CREATE TABLE IF NOT EXISTS logs (
    id              BIGSERIAL,
    tenant_id       VARCHAR(64) NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip       INET,
    destination_ip  INET,
    source_port     INTEGER,
    destination_port INTEGER,
    protocol        VARCHAR(16),
    action          VARCHAR(32),
    log_type        VARCHAR(64),
    vendor          VARCHAR(64),
    device_hostname VARCHAR(128),
    severity        VARCHAR(16) DEFAULT 'low',
    message         TEXT,
    raw_data        JSONB,
    business_context JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    
    -- Partition key MUST be part of primary key
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create partitions for current and next 3 months
-- Production: Use pg_partman or cron job for auto-creation
CREATE TABLE IF NOT EXISTS logs_2026_02 PARTITION OF logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE IF NOT EXISTS logs_2026_03 PARTITION OF logs
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS logs_2026_04 PARTITION OF logs
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE IF NOT EXISTS logs_2026_05 PARTITION OF logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- Default partition for data outside defined ranges
CREATE TABLE IF NOT EXISTS logs_default PARTITION OF logs DEFAULT;

-- =============================================================================
-- INDEXES
-- =============================================================================
-- Strategy: Composite indexes for common query patterns
-- =============================================================================

-- Primary query pattern: Filter by tenant + time range
CREATE INDEX IF NOT EXISTS idx_logs_tenant_timestamp 
    ON logs (tenant_id, timestamp DESC);

-- IP-based lookups for threat correlation
CREATE INDEX IF NOT EXISTS idx_logs_source_ip 
    ON logs (source_ip) WHERE source_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_logs_dest_ip 
    ON logs (destination_ip) WHERE destination_ip IS NOT NULL;

-- Log type filtering (firewall, auth, etc.)
CREATE INDEX IF NOT EXISTS idx_logs_type_tenant 
    ON logs (log_type, tenant_id);

-- Severity-based queries (dashboard widgets)
CREATE INDEX IF NOT EXISTS idx_logs_severity 
    ON logs (severity, timestamp DESC);

-- JSONB index for business_context queries
CREATE INDEX IF NOT EXISTS idx_logs_business_context 
    ON logs USING GIN (business_context jsonb_path_ops);

-- =============================================================================
-- DEAD LETTERS TABLE (Failed Validation Logs)
-- =============================================================================
-- No partitioning needed: Low volume, audit/debug only
-- =============================================================================

CREATE TABLE IF NOT EXISTS dead_letters (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64),
    received_at     TIMESTAMPTZ DEFAULT NOW(),
    source_queue    VARCHAR(64),
    error_type      VARCHAR(64),
    error_message   TEXT,
    raw_payload     JSONB NOT NULL,
    retry_count     INTEGER DEFAULT 0,
    last_retry_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dead_letters_tenant 
    ON dead_letters (tenant_id, received_at DESC);

-- =============================================================================
-- ALERTS TABLE (Security Alerts)
-- =============================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    alert_type      VARCHAR(64) NOT NULL,
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',
    source_ip       INET,
    destination_ip  INET,
    description     TEXT,
    details         JSONB,
    status          VARCHAR(32) DEFAULT 'open',
    notified        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status 
    ON alerts (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity 
    ON alerts (severity, created_at DESC);

-- =============================================================================
-- THREAT INTELLIGENCE TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id              BIGSERIAL PRIMARY KEY,
    indicator_type  VARCHAR(32) NOT NULL,  -- ip, domain, hash
    indicator_value VARCHAR(256) NOT NULL,
    threat_type     VARCHAR(64),
    confidence      FLOAT,
    source          VARCHAR(128),
    description     TEXT,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    is_active       BOOLEAN DEFAULT TRUE,
    UNIQUE (indicator_type, indicator_value)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_value 
    ON threat_intelligence (indicator_value) WHERE is_active = TRUE;

-- =============================================================================
-- TENANTS TABLE (Multi-Tenant Config)
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64) UNIQUE NOT NULL,
    name            VARCHAR(128) NOT NULL,
    settings        JSONB DEFAULT '{}',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- USERS TABLE (Authentication)
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    username        VARCHAR(64) UNIQUE NOT NULL,
    email           VARCHAR(128) UNIQUE NOT NULL,
    password_hash   VARCHAR(256) NOT NULL,
    role            VARCHAR(32) DEFAULT 'analyst',
    is_superadmin   BOOLEAN DEFAULT FALSE,
    functionalities JSONB DEFAULT '[]',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_tenant 
    ON users (tenant_id);

-- =============================================================================
-- ROW-LEVEL SECURITY (Tenant Isolation)
-- =============================================================================
-- Prevents cross-tenant data access at database level
-- Application sets: SET app.current_tenant = 'tenant_123';
-- =============================================================================

ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE dead_letters ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their tenant's data
CREATE POLICY tenant_isolation_logs ON logs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', TRUE));

CREATE POLICY tenant_isolation_alerts ON alerts
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', TRUE));

CREATE POLICY tenant_isolation_dead ON dead_letters
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', TRUE));

-- =============================================================================
-- REPORTS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS reports (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64),
    report_type     VARCHAR(32) NOT NULL,
    start_date      TIMESTAMPTZ NOT NULL,
    end_date        TIMESTAMPTZ NOT NULL,
    total_logs      INTEGER,
    total_alerts    INTEGER,
    alerts_by_severity JSONB,
    top_source_ips  JSONB,
    top_alert_types JSONB,
    file_path       VARCHAR(256),
    summary         JSONB,
    format          VARCHAR(20),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- HELPER FUNCTION: Create Monthly Partition
-- =============================================================================
-- Usage: SELECT create_logs_partition('2026-06');
-- =============================================================================

CREATE OR REPLACE FUNCTION create_logs_partition(partition_month TEXT)
RETURNS VOID AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    -- Parse month (YYYY-MM format)
    start_date := (partition_month || '-01')::DATE;
    end_date := start_date + INTERVAL '1 month';
    partition_name := 'logs_' || TO_CHAR(start_date, 'YYYY_MM');
    
    -- Create partition if not exists
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF logs FOR VALUES FROM (%L) TO (%L)',
        partition_name,
        start_date,
        end_date
    );
    
    RAISE NOTICE 'Created partition: %', partition_name;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Insert Default Admin User (Development Only)
-- =============================================================================
-- Password: admin123 (pbkdf2_sha256 hash)
-- =============================================================================

INSERT INTO tenants (tenant_id, name) 
VALUES ('default', 'Default Tenant')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO users (tenant_id, username, email, password_hash, role, is_superadmin)
VALUES (
    'default',
    'admin',
    'admin@siem.local',
    '$pbkdf2-sha256$29000$N2bMuXfO.V9r7d07B2DsXQ$8yQ7JPVE7nW5jBmSjMg3zUKBNjYVT9D5jMZ/1.GzFN0',
    'superadmin',
    TRUE
)
ON CONFLICT (username) DO NOTHING;

-- =============================================================================
-- GRANT PERMISSIONS
-- =============================================================================

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO siem_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO siem_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO siem_user;

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'SIEM Database initialized successfully!';
    RAISE NOTICE 'Partitions created: logs_2026_02 through logs_2026_05';
    RAISE NOTICE 'Row-Level Security enabled for: logs, alerts, dead_letters';
END $$;
