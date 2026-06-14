-- VertGuard JWT denylist (token revocation).
--
-- Idempotent. Operators revoke individual tokens (kind='jti') or entire
-- subjects (kind='sub'). Rows with non-null expires_at can be GC'd by an
-- external sweeper; sub-level revocations typically stay until cleared.

CREATE TABLE IF NOT EXISTS token_denylist (
    id          UUID         PRIMARY KEY,
    kind        TEXT         NOT NULL CHECK (kind IN ('jti','sub')),
    value       TEXT         NOT NULL,
    reason      TEXT,
    revoked_by  TEXT,
    revoked_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_token_denylist_kind_value
    ON token_denylist (kind, value);

CREATE INDEX IF NOT EXISTS idx_token_denylist_expires_at
    ON token_denylist (expires_at);

INSERT INTO schema_migrations (version, name) VALUES (5, '005_token_denylist')
    ON CONFLICT (version) DO NOTHING;
