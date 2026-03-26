-- NIS2 Compass — canonical PostgreSQL schema
-- Generated from Alembic migrations; do not run directly.
-- Use: alembic upgrade head
--
-- Last updated to reflect migrations 001–012.

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ENUM types
CREATE TYPE org_size        AS ENUM ('micro', 'small', 'medium', 'large');
CREATE TYPE entity_type     AS ENUM ('essential', 'important');
CREATE TYPE assessment_status AS ENUM ('draft', 'in_progress', 'under_review', 'completed', 'archived');
CREATE TYPE control_status  AS ENUM ('not_assessed', 'compliant', 'partially_compliant', 'non_compliant', 'not_applicable');
CREATE TYPE artifact_type   AS ENUM ('policy', 'procedure', 'evidence', 'report', 'screenshot', 'log', 'certificate', 'contract');
CREATE TYPE nist_category   AS ENUM ('identify', 'protect', 'detect', 'respond', 'recover');
CREATE TYPE audit_risk_class AS ENUM ('INFO', 'WARNING', 'CRITICAL');

-- organisations: the companies being assessed under NIS2
CREATE TABLE organisations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    industry            VARCHAR(100) NOT NULL,   -- NIS2 sector (energy, transport, banking, health, digital_infra, etc.)
    country             CHAR(2)      NOT NULL,   -- ISO 3166-1 alpha-2
    size                org_size     NOT NULL DEFAULT 'medium',
    entity_type         entity_type  NOT NULL DEFAULT 'important',  -- essential vs important entity
    registration_number VARCHAR(100),
    contact_email       VARCHAR(255),
    created_by          VARCHAR(255),            -- added migration 008: owning actor for per-tenant name uniqueness
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
-- migration 011: scoped to (name, created_by) so different actors may reuse the same organisation name
CREATE UNIQUE INDEX idx_organisations_name     ON organisations(name, created_by);
CREATE INDEX idx_organisations_country  ON organisations(country);
CREATE INDEX idx_organisations_industry ON organisations(industry);

-- assessments: a single NIS2 Article 21 compliance assessment for an organisation
CREATE TABLE assessments (
    id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID          NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    title             VARCHAR(255)  NOT NULL,
    status            assessment_status NOT NULL DEFAULT 'draft',
    framework_version VARCHAR(20)   NOT NULL DEFAULT 'NIS2-2022/0383',
    scope             TEXT,
    assessor          VARCHAR(255),
    due_date          DATE,
    completed_at      TIMESTAMPTZ,
    created_by        VARCHAR(255),             -- added migration 008: records which actor created the assessment
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_assessments_org_id ON assessments(org_id);
CREATE INDEX idx_assessments_status ON assessments(status);

-- controls: NIS2 Article 21 measures (a–j), each mapped to a NIST CSF category
CREATE TABLE controls (
    id                   UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id        UUID           NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    article_ref          VARCHAR(20)    NOT NULL,  -- e.g. 'Art.21(2)(a)'
    measure_ref          CHAR(1)        NOT NULL CHECK (measure_ref IN ('a','b','c','d','e','f','g','h','i','j')),
    nist_category        nist_category  NOT NULL,
    title                VARCHAR(255)   NOT NULL,
    description          TEXT,
    status               control_status NOT NULL DEFAULT 'not_assessed',
    evidence             JSONB          NOT NULL DEFAULT '{}',
    gap_description      TEXT,
    remediation_plan     TEXT,
    remediation_due      DATE,
    risk_score           NUMERIC(3,1)   CHECK (risk_score >= 0.0 AND risk_score <= 10.0),
    notes                TEXT,
    -- remediation workflow fields added in migration 006
    remediation_owner    VARCHAR(255),
    remediation_status   VARCHAR(20)    DEFAULT 'not_started'
                             CHECK (remediation_status IN ('not_started', 'in_progress', 'blocked', 'completed')),
    external_ticket_url  TEXT           CHECK (external_ticket_url IS NULL OR external_ticket_url LIKE 'http%'),
    remediation_notes    TEXT,
    assessed_by          VARCHAR(255),
    assessed_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    -- migration 007: one measure per assessment
    CONSTRAINT uq_controls_assessment_measure UNIQUE (assessment_id, measure_ref)
);
CREATE INDEX idx_controls_assessment_id ON controls(assessment_id);
CREATE INDEX idx_controls_status        ON controls(status);
CREATE INDEX idx_controls_measure_ref   ON controls(measure_ref);
CREATE INDEX idx_controls_nist_category ON controls(nist_category);

-- artifacts: evidence files uploaded against an assessment or specific control
CREATE TABLE artifacts (
    id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID          NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    control_id    UUID          REFERENCES controls(id) ON DELETE SET NULL,
    type          artifact_type NOT NULL,
    filename      VARCHAR(255)  NOT NULL,
    file_path     VARCHAR(1024) NOT NULL,
    hash          CHAR(64)      NOT NULL,   -- SHA-256 hex of file content
    size_bytes    BIGINT,
    mime_type     VARCHAR(100),
    description   TEXT,
    created_by    VARCHAR(255)  NOT NULL,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_artifacts_assessment_id ON artifacts(assessment_id);
CREATE INDEX idx_artifacts_control_id    ON artifacts(control_id);
CREATE INDEX idx_artifacts_hash          ON artifacts(hash);

-- api_keys: API keys for machine-to-machine authentication
CREATE TABLE api_keys (
    id           UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash     CHAR(64)      NOT NULL UNIQUE,  -- SHA-256 hex of plaintext key
    label        VARCHAR(100),
    scope        VARCHAR(20)   NOT NULL DEFAULT 'read_write' CHECK (scope IN ('read', 'read_write')),
    is_active    BOOLEAN       NOT NULL DEFAULT TRUE,
    created_by   VARCHAR(255),
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ               -- added migration 010; NULL = never expires
);
CREATE INDEX idx_api_keys_key_hash  ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);

-- control_templates: built-in NIS2 Article 21 measure definitions (added migration 005)
CREATE TABLE control_templates (
    id            SERIAL        PRIMARY KEY,
    measure_ref   CHAR(1)       NOT NULL UNIQUE,
    article_ref   VARCHAR(20)   NOT NULL,
    title         VARCHAR(255)  NOT NULL,
    description   TEXT          NOT NULL,
    nist_category VARCHAR(20)   NOT NULL,
    guidance      TEXT
);
CREATE INDEX idx_control_templates_measure_ref ON control_templates(measure_ref);

-- audit_log: CITADEL-compatible append-only evidence ledger
-- Enforced immutable via trigger (no UPDATE, no DELETE — mirrors CITADEL WORM log spec).
-- hash_version=1: chain_hash = SHA-256(id + action + actor + resource_type + resource_id + prev_hash + timestamp)  [bare concat, legacy]
-- hash_version=2: chain_hash = SHA-256(id || action || actor || resource_type || resource_id || prev_hash || timestamp)  [|| delimiters, current]
-- Column default is 1 (migration 009): pre-existing rows are stamped 1 automatically; new rows are
-- inserted with hash_version=2 explicitly set by the application (audit.write_audit()).
CREATE SEQUENCE IF NOT EXISTS audit_log_seq_seq;  -- added migration 012
CREATE TABLE audit_log (
    id                  UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    seq                 BIGINT         NOT NULL DEFAULT nextval('audit_log_seq_seq'),  -- added migration 012: monotonic ordering key
    action              VARCHAR(100)   NOT NULL,   -- e.g. assessment_created, control_updated
    actor               VARCHAR(255)   NOT NULL,
    resource_type       VARCHAR(100)   NOT NULL,
    resource_id         UUID,
    risk_class          audit_risk_class NOT NULL DEFAULT 'INFO',
    metadata            JSONB          NOT NULL DEFAULT '{}',
    object_fingerprint  CHAR(64),                 -- SHA-256 of object canonical JSON at time of action
    prev_hash           CHAR(64),                 -- chain_hash of the previous entry (NULL for genesis)
    chain_hash          CHAR(64)       NOT NULL,  -- SHA-256 chain anchor
    hash_version        SMALLINT       NOT NULL DEFAULT 1,  -- added migration 009; 1=legacy bare concat, 2=|| delimiters
    timestamp           TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);
ALTER SEQUENCE audit_log_seq_seq OWNED BY audit_log.seq;
CREATE INDEX idx_audit_log_actor         ON audit_log(actor);
CREATE INDEX idx_audit_log_action        ON audit_log(action);
CREATE INDEX idx_audit_log_resource_id   ON audit_log(resource_id);
CREATE INDEX idx_audit_log_timestamp     ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_seq           ON audit_log(seq);  -- added migration 012

-- Immutability enforcement (CITADEL WORM log pattern)
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is immutable: % operations are not permitted', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_audit_log_immutability
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_immutable();

-- updated_at auto-update trigger for mutable tables
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_organisations_updated_at BEFORE UPDATE ON organisations FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_assessments_updated_at   BEFORE UPDATE ON assessments   FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_controls_updated_at      BEFORE UPDATE ON controls      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
