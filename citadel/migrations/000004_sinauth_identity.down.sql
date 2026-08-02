-- CITADEL — revert sinauth identity bridge.
--
-- NOTE: best-effort rollback only. Once sinauth-issued UUID user_ids have
-- been written to rate_counters/signing_keys, the ALTER ... USING ::BIGINT
-- casts below will fail (a UUID string is not a valid bigint literal). This
-- down migration is safe to run only against a database that has not yet
-- accumulated real sinauth identities (e.g. immediately after 'up', in CI/
-- local dev). Recovering a populated environment requires a hand-written,
-- data-aware migration instead of a blind type revert.

BEGIN;

ALTER TABLE rate_counters ALTER COLUMN user_id TYPE BIGINT USING user_id::BIGINT;
ALTER TABLE signing_keys  ALTER COLUMN user_id TYPE BIGINT USING user_id::BIGINT;

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

COMMIT;
