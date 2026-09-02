-- sinauth: TOTP backup codes, login challenges, and brute-force lockout.
--
-- Complements 007_totp.sql (totp_credentials / totp_setup_sessions, which
-- already existed with zero Go code reading or writing them). This
-- migration adds the pieces the real enrollment/login/disable flow needs:
--
--   * totp_backup_codes     — single-use recovery codes issued once at
--                              enrollment confirmation, stored as bcrypt
--                              hashes only (never plaintext).
--   * totp_login_challenges — the server-side state for the two-phase
--                              login flow: password auth succeeds but does
--                              not issue a token when TOTP is enabled;
--                              instead a short-lived challenge is created,
--                              and a second call with a TOTP/backup code
--                              (POST /api/v1/mfa/totp/login/verify)
--                              redeems it for a token.
--   * failed_attempts / locked_until on totp_credentials — per-account
--                              lockout after repeated bad codes, since a
--                              6-digit TOTP code is brute-forceable without
--                              one (see internal/mfa/totp.go).

CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast lookup of a user's still-usable backup codes at verification time.
CREATE INDEX IF NOT EXISTS idx_totp_backup_codes_user_unused
    ON totp_backup_codes(user_id) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS totp_login_challenges (
    challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at   TIMESTAMPTZ NOT NULL DEFAULT now() + interval '5 minutes'
);

ALTER TABLE totp_credentials
    ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
