-- sinauth: short-lived authorization codes (5 min TTL, one-time)
CREATE TABLE IF NOT EXISTS authorization_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    nonce                 TEXT,
    expires_at            TIMESTAMPTZ NOT NULL,
    used                  BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS auth_codes_expires_idx ON authorization_codes (expires_at);
