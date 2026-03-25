CREATE TYPE audit_action AS ENUM (
    'scan_created', 'scan_started', 'scan_completed', 'scan_failed', 'scan_deleted',
    'finding_triaged', 'finding_status_changed',
    'spec_uploaded', 'spec_parsed',
    'api_key_created', 'api_key_revoked',
    'user_login', 'user_logout',
    'config_changed',
    'report_generated', 'report_exported'
);

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
