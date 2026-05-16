-- Guardian Pi — TimescaleDB Initialization
-- Time-series storage for telemetry and metrics

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Raw telemetry events
CREATE TABLE telemetry_events (
    time        TIMESTAMPTZ      NOT NULL,
    device_id   TEXT             NOT NULL,
    event_type  TEXT             NOT NULL,
    severity    TEXT             DEFAULT 'info',
    title       TEXT,
    details     JSONB,
    agent_version TEXT
);

SELECT create_hypertable('telemetry_events', 'time');

-- Create indexes for common queries
CREATE INDEX idx_telemetry_device ON telemetry_events (device_id, time DESC);
CREATE INDEX idx_telemetry_severity ON telemetry_events (severity, time DESC);
CREATE INDEX idx_telemetry_type ON telemetry_events (event_type, time DESC);

-- System metrics (CPU, RAM, disk)
CREATE TABLE system_metrics (
    time            TIMESTAMPTZ     NOT NULL,
    device_id       TEXT            NOT NULL,
    cpu_percent     DOUBLE PRECISION,
    ram_percent     DOUBLE PRECISION,
    disk_percent    DOUBLE PRECISION,
    connection_count INTEGER,
    process_count   INTEGER
);

SELECT create_hypertable('system_metrics', 'time');
CREATE INDEX idx_metrics_device ON system_metrics (device_id, time DESC);

-- Continuous aggregate: hourly device metrics
CREATE MATERIALIZED VIEW device_metrics_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    device_id,
    AVG(cpu_percent) AS avg_cpu,
    MAX(cpu_percent) AS max_cpu,
    AVG(ram_percent) AS avg_ram,
    MAX(ram_percent) AS max_ram,
    AVG(disk_percent) AS avg_disk,
    MAX(connection_count) AS max_connections
FROM system_metrics
GROUP BY bucket, device_id;

-- Continuous aggregate: daily alert summary
CREATE MATERIALIZED VIEW alert_summary_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS bucket,
    device_id,
    severity,
    COUNT(*) AS alert_count
FROM telemetry_events
WHERE severity IN ('critical', 'high', 'medium', 'low')
GROUP BY bucket, device_id, severity;

-- Retention policy: keep raw data 90 days, aggregates 1 year
SELECT add_retention_policy('telemetry_events', INTERVAL '90 days');
SELECT add_retention_policy('system_metrics', INTERVAL '90 days');

-- Compression policy: compress data older than 7 days
ALTER TABLE telemetry_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id'
);
SELECT add_compression_policy('telemetry_events', INTERVAL '7 days');

ALTER TABLE system_metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id'
);
SELECT add_compression_policy('system_metrics', INTERVAL '7 days');
