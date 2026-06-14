-- VertGuard per-subject rate-limit overrides.
--
-- Idempotent. Operators tighten or loosen the per-key token-bucket rate
-- for a specific subject (kind='sub') or source IP (kind='ip'). Rows
-- with non-null expires_at can be GC'd by an external sweeper; entries
-- without an expiry stay until cleared explicitly.

CREATE TABLE IF NOT EXISTS rate_limit_overrides (
    id          UUID              PRIMARY KEY,
    kind        TEXT              NOT NULL CHECK (kind IN ('sub','ip')),
    value       TEXT              NOT NULL,
    rps         DOUBLE PRECISION  NOT NULL,
    burst       INTEGER           NOT NULL,
    reason      TEXT,
    created_by  TEXT,
    created_at  TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rate_limit_overrides_kind_value
    ON rate_limit_overrides (kind, value);

CREATE INDEX IF NOT EXISTS idx_rate_limit_overrides_expires_at
    ON rate_limit_overrides (expires_at);

INSERT INTO schema_migrations (version, name) VALUES (6, '006_rate_limit_overrides')
    ON CONFLICT (version) DO NOTHING;
