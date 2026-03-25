-- =============================================================================
-- APIGuard — Consolidated Reference Schema
-- =============================================================================
-- This file represents the complete database schema as it exists after all
-- numbered migration files (001–006) have been applied in order. It is
-- provided for documentation and reference purposes only.
--
-- DO NOT apply this file directly against a database. The canonical source of
-- truth is the numbered migration files:
--
--   001_create_scans.up.sql
--   002_create_findings.up.sql
--   003_create_api_inventory.up.sql
--   004_create_api_specs.up.sql
--   005_create_audit_log.up.sql
--   006_add_api_spec_id_to_scans.up.sql
--
-- Last updated to reflect: migration 006
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');

CREATE TYPE report_format AS ENUM ('json', 'html', 'pdf', 'sarif');

CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

CREATE TYPE finding_status AS ENUM ('open', 'confirmed', 'false_positive', 'accepted', 'fixed');

CREATE TYPE audit_action AS ENUM (
    'scan_created', 'scan_started', 'scan_completed', 'scan_failed', 'scan_deleted',
    'finding_triaged', 'finding_status_changed',
    'spec_uploaded', 'spec_parsed',
    'api_key_created', 'api_key_revoked',
    'user_login', 'user_logout',
    'config_changed',
    'report_generated', 'report_exported'
);

-- ---------------------------------------------------------------------------
-- Table: api_specs  (migration 004)
-- Stores parsed OpenAPI spec metadata, decoupled from individual scans so
-- the same spec can be reused across multiple scans without re-parsing.
-- ---------------------------------------------------------------------------
CREATE TABLE api_specs (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spec_hash      VARCHAR(64) NOT NULL UNIQUE,          -- SHA-256 of raw spec content
    spec_url       TEXT,                                  -- origin URL if fetched remotely
    spec_format    VARCHAR(20) NOT NULL DEFAULT 'openapi3', -- openapi3 | swagger2 | graphql
    title          TEXT,
    version        TEXT,
    base_url       TEXT,
    endpoint_count INT NOT NULL DEFAULT 0,
    auth_schemes   JSONB NOT NULL DEFAULT '[]',           -- parsed auth scheme names
    raw_spec       TEXT,                                  -- raw spec content (nullable — large)
    parsed_ir      JSONB NOT NULL DEFAULT '{}',           -- parsed APIGuard IR
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_specs_spec_hash  ON api_specs(spec_hash);
CREATE INDEX idx_api_specs_created_at ON api_specs(created_at DESC);

-- ---------------------------------------------------------------------------
-- Table: scans  (migration 001 + api_spec_id column from migration 006)
-- ---------------------------------------------------------------------------
CREATE TABLE scans (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spec_url    TEXT,
    spec_hash   VARCHAR(64),                              -- SHA-256
    target_url  TEXT NOT NULL,
    status      scan_status NOT NULL DEFAULT 'pending',
    modules     TEXT[] NOT NULL DEFAULT '{}',
    started_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Config snapshot
    config_json JSONB NOT NULL DEFAULT '{}',

    -- Summary (populated on completion)
    total_findings INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count     INT DEFAULT 0,
    medium_count   INT DEFAULT 0,
    low_count      INT DEFAULT 0,
    info_count     INT DEFAULT 0,

    -- Auth config (no secrets stored)
    auth_type   VARCHAR(20),

    -- Error info (populated on failure)
    error_message TEXT,

    -- Link to parsed spec record (migration 006; nullable — pre-existing scans remain valid)
    api_spec_id UUID REFERENCES api_specs(id) ON DELETE SET NULL
);

CREATE INDEX idx_scans_status       ON scans(status);
CREATE INDEX idx_scans_created_at   ON scans(created_at DESC);
CREATE INDEX idx_scans_target_url   ON scans(target_url);
CREATE INDEX idx_scans_api_spec_id  ON scans(api_spec_id);

-- ---------------------------------------------------------------------------
-- Table: findings  (migration 002 + owasp_category column from migration 006)
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    -- OWASP classification
    owasp_id        VARCHAR(10) NOT NULL,                 -- A1, A2, ..., A10
    module_id       VARCHAR(50) NOT NULL,                 -- a1_bola, a2_auth, etc.
    owasp_category  TEXT,                                 -- human-readable OWASP category name (migration 006)

    -- Finding details
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        finding_severity NOT NULL,

    -- CVSS
    cvss_score      DECIMAL(3,1) NOT NULL DEFAULT 0.0,
    cvss_vector     VARCHAR(100),

    -- Location
    endpoint_path   TEXT NOT NULL,
    endpoint_method VARCHAR(10) NOT NULL,

    -- Evidence
    evidence_request  TEXT,                               -- HTTP request that triggered the finding
    evidence_response TEXT,                               -- HTTP response proving the finding
    evidence_json     JSONB,                              -- structured evidence

    -- Remediation
    remediation TEXT,

    -- Triage
    status      finding_status NOT NULL DEFAULT 'open',
    triaged_by  VARCHAR(255),
    triaged_at  TIMESTAMPTZ,
    triage_note TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_id   ON findings(scan_id);
CREATE INDEX idx_findings_severity  ON findings(severity);
CREATE INDEX idx_findings_status    ON findings(status);
CREATE INDEX idx_findings_module_id ON findings(module_id);
CREATE INDEX idx_findings_owasp_id  ON findings(owasp_id);

-- ---------------------------------------------------------------------------
-- Table: api_inventory  (migration 003)
-- ---------------------------------------------------------------------------
CREATE TABLE api_inventory (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_url     TEXT NOT NULL UNIQUE,
    spec_hash      VARCHAR(64),                           -- latest known spec hash
    api_version    VARCHAR(50),
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at TIMESTAMPTZ,
    scan_count     INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Table: audit_log  (migration 005)
-- CITADEL WORM — append-only integrity log.
-- UPDATE and DELETE are silently blocked by PostgreSQL rules.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Actor
    actor_id      TEXT NOT NULL,                          -- user ID or system/api-key identifier
    actor_type    VARCHAR(20) NOT NULL DEFAULT 'user',    -- user | system | api_key

    -- Action
    action        audit_action NOT NULL,
    resource_type VARCHAR(50) NOT NULL,                   -- scans | findings | api_specs | etc.
    resource_id   UUID,                                   -- nullable (e.g. config changes)

    -- Context
    ip_address    INET,
    user_agent    TEXT,

    -- Payload
    before_state  JSONB,                                  -- state before change (nullable)
    after_state   JSONB,                                  -- state after change (nullable)
    metadata      JSONB NOT NULL DEFAULT '{}',            -- extra structured context

    -- Chain anchor (CITADEL integrity)
    prev_hash     VARCHAR(64),                            -- SHA-256 of previous row's chain_hash
    chain_hash    VARCHAR(64) NOT NULL,                   -- SHA-256(id||actor_id||action||resource_id||prev_hash||created_at)

    -- Timestamp — immutable
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Append-only enforcement: prevent UPDATE and DELETE
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- Indexes for common queries
CREATE INDEX idx_audit_log_actor_id   ON audit_log(actor_id);
CREATE INDEX idx_audit_log_action     ON audit_log(action);
CREATE INDEX idx_audit_log_resource   ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
