-- sinauth: SSO browser sessions (one login = access to all clients)
CREATE TABLE IF NOT EXISTS sso_sessions (
    id         TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sso_sessions_expires_idx ON sso_sessions (expires_at);
CREATE INDEX IF NOT EXISTS sso_sessions_user_idx    ON sso_sessions (user_id);
