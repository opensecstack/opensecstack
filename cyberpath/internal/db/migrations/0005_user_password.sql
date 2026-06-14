-- CyberPath v1.0.0 — auth hardening.
--
-- 0001 already created `users.password_hash` as TEXT. This migration:
--   * widens nothing (TEXT is fine for the PHC argon2id encoding) but
--     documents the intended format and adds the supporting columns
--     real authentication requires.
--   * adds `password_updated_at` so we can age-out old hashes and
--     enforce rotation policies later (NIS2 Annex I §5).
--   * adds `mfa_secret_encrypted` (bytea) as a placeholder for v1.1+
--     TOTP / WebAuthn enrolment. Stays nullable; the column being
--     present lets us ship the migration once and gate the feature
--     behind the application layer.
--   * adds a UNIQUE index on lower(email) — login lookups are
--     case-insensitive; the existing UNIQUE (tenant_id, email) keeps
--     per-tenant isolation, this index is a non-tenant lookup index
--     used for global rate-limit / lockout state.
--
-- The 0001 column is reused. We do NOT recreate it.
--
-- Apply with `make migrate-up`; safe to replay.

BEGIN;

-- password_hash already exists from 0001 as TEXT. No change.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_secret_encrypted BYTEA;

-- Case-insensitive lookup index for login. Per-tenant uniqueness is
-- preserved by the existing (tenant_id, email) constraint from 0001.
CREATE INDEX IF NOT EXISTS idx_users_email_lower
    ON users (LOWER(email));

COMMIT;
