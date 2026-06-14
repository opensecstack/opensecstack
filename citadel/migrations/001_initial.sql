-- CITADEL v1.0.0 — Initial Schema
-- Append-only enforcement via PostgreSQL rules (no UPDATE, no DELETE on worm_entries)

BEGIN;

-- ── WORM ENTRIES ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS worm_entries (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence_num BIGINT      NOT NULL UNIQUE,
    ts_utc       TIMESTAMPTZ NOT NULL DEFAULT now(),
    source       TEXT        NOT NULL,
    event_type   TEXT        NOT NULL,
    project_id   TEXT        NOT NULL DEFAULT '',
    payload      BYTEA       NOT NULL DEFAULT '',
    triple_hash  TEXT        NOT NULL,  -- hex(SHA256||SHA512||BLAKE3) = 256 hex chars
    chain_hash   TEXT        NOT NULL,  -- hex(SHA256(prev_hash || payload_bytes))
    prev_hash    TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sequence counter for WORM entries (guarantees monotonic ordering)
CREATE SEQUENCE IF NOT EXISTS worm_seq START 1;

-- Enforce append-only: block UPDATE and DELETE on worm_entries
CREATE OR REPLACE RULE worm_no_update AS
    ON UPDATE TO worm_entries DO INSTEAD NOTHING;

CREATE OR REPLACE RULE worm_no_delete AS
    ON DELETE TO worm_entries DO INSTEAD NOTHING;

-- Indexes for chain verification and query
CREATE INDEX IF NOT EXISTS idx_worm_sequence  ON worm_entries (sequence_num);
CREATE INDEX IF NOT EXISTS idx_worm_ts        ON worm_entries (ts_utc);
CREATE INDEX IF NOT EXISTS idx_worm_source    ON worm_entries (source);
CREATE INDEX IF NOT EXISTS idx_worm_project   ON worm_entries (project_id);

-- ── MARSHAL DECISIONS ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS marshal_decisions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID        NOT NULL UNIQUE,
    outcome      TEXT        NOT NULL CHECK (outcome IN ('EXECUTE','REFUSE','HARD_STOP')),
    kerkese      JSONB       NOT NULL DEFAULT '{}',
    gates        JSONB       NOT NULL DEFAULT '[]',
    worm_entry_id UUID       REFERENCES worm_entries(id),
    ts_utc       TIMESTAMPTZ NOT NULL DEFAULT now(),
    dry_run      BOOLEAN     NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_marshal_outcome    ON marshal_decisions (outcome);
CREATE INDEX IF NOT EXISTS idx_marshal_ts         ON marshal_decisions (ts_utc);
CREATE INDEX IF NOT EXISTS idx_marshal_execution  ON marshal_decisions (execution_id);

-- ── WORM ANCHORS ─────────────────────────────────────────────────────────────
-- Every 100 WORM entries, the chain_hash is signed with the CITADEL master Ed25519 key.
CREATE TABLE IF NOT EXISTS anchors (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence_num BIGINT      NOT NULL REFERENCES worm_entries(sequence_num),
    chain_hash   TEXT        NOT NULL,
    ed25519_sig  TEXT        NOT NULL,  -- hex-encoded Ed25519 signature
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_anchors_sequence ON anchors (sequence_num);

-- ── SESSIONS (for Gate 1 AuthN) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    BIGINT      NOT NULL,
    role       TEXT        NOT NULL,
    role_group TEXT        NOT NULL DEFAULT 'default',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

-- ── RATE LIMIT COUNTERS (for Gate 4 AUGUR rule_02) ───────────────────────────
CREATE TABLE IF NOT EXISTS rate_counters (
    user_id    BIGINT      NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    count      INT         NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, window_end)
);

COMMIT;
