-- CyberPath audit + content-versions + webhooks + outbox.
--
-- This migration introduces the four cross-cutting tables that back
-- CyberPath's audit-by-design posture:
--
--   * content_versions — append-only, immutable snapshots of every
--     track/module/lesson/quiz/lab payload. Completion records
--     reference these by id so an auditor can independently
--     reproduce the exact body of evidence the learner saw, years
--     after the fact. UPDATE is allowed only to set superseded_at;
--     DELETE is forbidden by trigger (see below).
--
--   * audit_events — generic internal app audit log for every
--     state-changing API call (track edits, cohort enrolments, lab
--     starts, certification revocations, …). Distinct from the
--     CITADEL outbox: audit_events is CyberPath's own operational
--     trail; the outbox is the durable queue that ships canonical
--     evidence to CITADEL's WORM ledger. Retention: 7 years (NIS2
--     default audit-trail window, see docs/data-model.md).
--
--   * webhooks — outbound webhook subscribers (e.g. NIS2 Compass
--     coverage push, IRFlow remediation feedback, instructor
--     cohort-completion notifications). HMAC-SHA256 signed per the
--     ecosystem-wide pattern (timestamp + "." + raw_body); secret
--     rotation procedure documented in the operator handbook.
--
--   * outbox — transactional outbox: CITADEL submissions and
--     reliable webhook delivery share this queue. Worker semantics
--     are documented inline on the table.
--
-- Apply with `make migrate-up`. IF NOT EXISTS is used throughout so
-- this can be replayed safely against a clean DB.

BEGIN;

-- ── content_versions ──────────────────────────────────────────────
-- Append-only snapshot table. One row per (entity_type, entity_id,
-- version). entity_id is varchar(128) so it can hold both UUIDs
-- (tracks/modules/lessons/quizzes) and slug-style ids (lab
-- definitions). content_hash is a sha256 hex digest over the
-- canonicalised payload — completions reference these snapshots,
-- so removing a row would break audit reproducibility.
--
-- IMMUTABILITY RULE: rows in this table MUST NOT be deleted. The
-- only mutation permitted is setting `superseded_at` when a newer
-- version is published. A trigger below raises on DELETE.
CREATE TABLE IF NOT EXISTS content_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type     VARCHAR(16) NOT NULL
                    CHECK (entity_type IN ('track','module','lesson','quiz','lab')),
    entity_id       VARCHAR(128) NOT NULL,
    version         INTEGER NOT NULL,
    content_hash    VARCHAR(64) NOT NULL,
    payload         JSONB NOT NULL,
    published_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by    UUID REFERENCES users(id) ON DELETE RESTRICT,
    superseded_at   TIMESTAMPTZ,
    change_summary  TEXT NOT NULL DEFAULT '',
    UNIQUE (entity_type, entity_id, version)
);
CREATE INDEX IF NOT EXISTS idx_content_versions_entity
    ON content_versions(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_content_versions_hash
    ON content_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_content_versions_published_at
    ON content_versions(published_at);

-- Immutability trigger: forbid DELETE on content_versions. Removing
-- a snapshot would break the audit chain because completions hold
-- foreign-key references to specific (entity, version) rows.
CREATE OR REPLACE FUNCTION content_versions_forbid_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'content_versions is append-only: DELETE is forbidden (row id=%)', OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_content_versions_no_delete ON content_versions;
CREATE TRIGGER trg_content_versions_no_delete
    BEFORE DELETE ON content_versions
    FOR EACH ROW EXECUTE FUNCTION content_versions_forbid_delete();

-- ── audit_events ──────────────────────────────────────────────────
-- Generic internal audit log. One row per state-changing API call.
-- tenant_id and actor_user_id are nullable so system-level events
-- (cron jobs, reconciliation sweeps, startup migrations) can be
-- recorded without a synthetic actor row. Retention: 7 years
-- (NIS2 default audit-trail window).
CREATE TABLE IF NOT EXISTS audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    actor_user_id   UUID REFERENCES users(id) ON DELETE RESTRICT,
    actor_role      VARCHAR(32) NOT NULL DEFAULT '',
    action          VARCHAR(64) NOT NULL,
    target_type     VARCHAR(32),
    target_id       VARCHAR(128),
    outcome         VARCHAR(16) NOT NULL
                    CHECK (outcome IN ('success','failure','denied')),
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    correlation_id  VARCHAR(64),
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant
    ON audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor
    ON audit_events(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_target
    ON audit_events(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation
    ON audit_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events(created_at);

-- ── webhooks ──────────────────────────────────────────────────────
-- Outbound webhook registrations. secret_hmac is the HMAC-SHA256
-- signing key used over `timestamp + "." + raw_body` (matches the
-- ecosystem-wide ThreatFlow / CITADEL / IRFlow scheme). secret
-- rotation policy: 90 days, with a 24h overlap window during which
-- both old and new secrets are accepted; secret_version is bumped
-- on each rotation. consecutive_failures backs the circuit-breaker
-- decision in the delivery worker.
CREATE TABLE IF NOT EXISTS webhooks (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL DEFAULT '',
    url                   TEXT NOT NULL,
    event_types           TEXT[] NOT NULL DEFAULT '{}',
    secret_hmac           VARCHAR(64) NOT NULL,
    secret_version        INTEGER NOT NULL DEFAULT 1,
    active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_success_at       TIMESTAMPTZ,
    last_failure_at       TIMESTAMPTZ,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant
    ON webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_active
    ON webhooks(active);

-- ── outbox ────────────────────────────────────────────────────────
-- Transactional outbox: CITADEL submissions + reliable webhook
-- delivery. bigint identity PK gives FIFO ordering across all
-- destinations. webhook_id is set only when destination references
-- a webhook row (NULL for pure CITADEL events).
--
-- Worker semantics:
--   1. Claim batch:
--        SELECT … FROM outbox
--          WHERE status = 'pending' AND next_attempt_at <= now()
--          ORDER BY id
--          FOR UPDATE SKIP LOCKED
--          LIMIT N;
--      and set status='in_flight' in the same txn.
--   2. Deliver each row (POST to CITADEL and/or webhook URL,
--      HMAC-SHA256 signed per the ecosystem scheme).
--   3. On success → status='delivered', delivered_at=now().
--   4. On failure → attempts := attempts + 1,
--      next_attempt_at := now() + exponential backoff
--      (e.g. 2^attempts seconds, capped), status reset to 'pending',
--      last_error populated.
--   5. After attempts > 10 → status='dlq' (manual triage; surfaces
--      via /metrics outbox_dlq_depth).
--
-- Retention: rows with status='delivered' may be GC'd 90 days after
-- delivered_at — the authoritative copy lives in CITADEL's WORM
-- ledger or in the receiving webhook target. DLQ rows are retained
-- until manually resolved.
CREATE TABLE IF NOT EXISTS outbox (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    destination     VARCHAR(16) NOT NULL
                    CHECK (destination IN ('citadel','webhook','both')),
    webhook_id      UUID REFERENCES webhooks(id) ON DELETE RESTRICT,
    event_type      VARCHAR(64) NOT NULL,
    payload         JSONB NOT NULL,
    correlation_id  VARCHAR(64),
    status          VARCHAR(16) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','in_flight','delivered','failed','dlq')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_status_next_attempt
    ON outbox(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_outbox_tenant
    ON outbox(tenant_id);
CREATE INDEX IF NOT EXISTS idx_outbox_correlation
    ON outbox(correlation_id);
CREATE INDEX IF NOT EXISTS idx_outbox_created_at
    ON outbox(created_at);

COMMIT;
