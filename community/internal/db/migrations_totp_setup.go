package db

const ddlTOTPSetupSessions = `
CREATE TABLE IF NOT EXISTS totp_setup_sessions (
    setup_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username   TEXT NOT NULL,
    secret     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes'
);
CREATE INDEX IF NOT EXISTS idx_totp_setup_sessions_username ON totp_setup_sessions(username);`
