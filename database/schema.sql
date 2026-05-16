-- Guardian Pi — Full Database Schema (PostgreSQL 16)
-- Run this to initialize all tables from scratch.
-- In production, use Alembic migrations instead.

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',  -- admin | analyst | viewer
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- ── Devices ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50) NOT NULL,          -- windows | linux | macos | raspberrypi | android | ios
    os_version VARCHAR(100),
    architecture VARCHAR(50),              -- x86_64 | arm64 | armv7l
    cpu_model VARCHAR(255),
    cpu_cores INTEGER,
    ram_mb INTEGER,
    storage_gb INTEGER,
    agent_version VARCHAR(50),
    status VARCHAR(50) NOT NULL DEFAULT 'registered',  -- registered | online | offline | compromised | quarantined
    is_virtual BOOLEAN DEFAULT FALSE,
    is_rooted BOOLEAN DEFAULT FALSE,
    api_key_hash TEXT,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    last_heartbeat TIMESTAMPTZ,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_os ON devices(os_type);
CREATE INDEX idx_devices_hostname ON devices(hostname);

-- ── Alerts ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',  -- critical | high | medium | low | info
    alert_type VARCHAR(100),                         -- malware | integrity | anomaly | policy | system
    status VARCHAR(50) NOT NULL DEFAULT 'open',      -- open | acknowledged | investigating | resolved | false_positive
    source VARCHAR(100) DEFAULT 'agent',
    details JSONB DEFAULT '{}'::jsonb,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_device ON alerts(device_id);
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_alerts_compound ON alerts(severity, status, created_at DESC);

-- ── Policies ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    rules JSONB NOT NULL,
    severity VARCHAR(50) DEFAULT 'medium',
    is_enabled BOOLEAN DEFAULT TRUE,
    target_os JSONB DEFAULT '["windows","linux","macos","raspberrypi"]'::jsonb,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Investigations ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'open',  -- open | in_progress | resolved | closed
    priority VARCHAR(50) NOT NULL DEFAULT 'medium',
    assignee_id UUID REFERENCES users(id),
    alert_ids JSONB,
    device_ids JSONB,
    timeline JSONB DEFAULT '[]'::jsonb,
    findings TEXT,
    mitre_tactics JSONB,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ
);

CREATE INDEX idx_investigations_status ON investigations(status);
CREATE INDEX idx_investigations_priority ON investigations(priority);

-- ── Audit Logs (Immutable) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    device_id UUID REFERENCES devices(id),
    action VARCHAR(255) NOT NULL,
    category VARCHAR(100) DEFAULT 'system',
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    hmac_signature VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent UPDATE and DELETE on audit_logs (immutability)
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER audit_log_immutable_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id);

-- ── Scan Results ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    scan_type VARCHAR(100) NOT NULL,   -- process | file | network | full
    status VARCHAR(50) DEFAULT 'completed',
    findings_count INTEGER DEFAULT 0,
    details JSONB DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Remediation Actions ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS remediation_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id),
    alert_id UUID REFERENCES alerts(id),
    action_type VARCHAR(100) NOT NULL,  -- quarantine_process | block_ip | isolate_device | rollback
    status VARCHAR(50) DEFAULT 'pending',
    parameters JSONB DEFAULT '{}'::jsonb,
    result JSONB,
    rollback_data JSONB,
    executed_by UUID REFERENCES users(id),
    executed_at TIMESTAMPTZ,
    rolled_back_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Default Admin User ──────────────────────────────────────
-- Password: GuardianPi2024! (bcrypt hash)
INSERT INTO users (email, hashed_password, full_name, role, is_active)
VALUES (
    'admin@guardianpi.io',
    '$2b$12$LQv3c1yqBo9SkvXS7QTJPe9Z0yEBiIQCjFp.3M1QMbwGg0K7RLKTS',
    'System Administrator',
    'admin',
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- ── Default Security Policies ───────────────────────────────
INSERT INTO policies (name, category, rules, severity, description) VALUES
(
    'Suspicious Process Detection',
    'endpoint',
    '{"type": "process_match", "patterns": ["mimikatz", "hydra", "john", "hashcat", "meterpreter", "cobalt"], "action": "alert"}',
    'critical',
    'Detects known offensive security tools running on endpoints'
),
(
    'File Integrity Monitoring',
    'compliance',
    '{"type": "file_integrity", "paths": ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/ssh/sshd_config"], "action": "alert"}',
    'high',
    'Monitors critical system files for unauthorized modifications'
),
(
    'Network Anomaly Detection',
    'network',
    '{"type": "connection_threshold", "max_connections": 200, "suspicious_ports": [4444, 5555, 1337, 31337], "action": "alert"}',
    'medium',
    'Detects unusual network connection patterns and suspicious ports'
),
(
    'USB Device Policy',
    'endpoint',
    '{"type": "usb_monitor", "allow_known": true, "alert_unknown": true, "action": "alert"}',
    'medium',
    'Monitors USB device connections and alerts on unknown devices'
) ON CONFLICT (name) DO NOTHING;
