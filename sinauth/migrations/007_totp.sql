-- sinauth: TOTP MFA
CREATE TABLE IF NOT EXISTS totp_credentials (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS totp_setup_sessions (
    setup_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes'
);
