BEGIN;

CREATE TABLE IF NOT EXISTS sessions (
    id                 TEXT         PRIMARY KEY,
    user_id            UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT         NOT NULL UNIQUE,
    issued_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ  NOT NULL,
    revoked_at         TIMESTAMPTZ,
    ip_address         TEXT,
    user_agent         TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

COMMIT;
