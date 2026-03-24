CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE report_format AS ENUM ('json', 'html', 'pdf', 'sarif');

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spec_url TEXT,
    spec_hash VARCHAR(64), -- SHA-256
    target_url TEXT NOT NULL,
    status scan_status NOT NULL DEFAULT 'pending',
    modules TEXT[] NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Config snapshot
    config_json JSONB NOT NULL DEFAULT '{}',

    -- Summary (populated on completion)
    total_findings INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    info_count INT DEFAULT 0,

    -- Auth config (no secrets stored)
    auth_type VARCHAR(20),

    -- Error info (populated on failure)
    error_message TEXT
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_target_url ON scans(target_url);
