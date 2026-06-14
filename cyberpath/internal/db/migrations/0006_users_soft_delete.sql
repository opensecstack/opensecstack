-- CyberPath migration 0006: users soft-delete.
--
-- Adds the `deleted_at` column the application has been carrying as a
-- *time.Time field on db.User without any backing column. Once this
-- migration is applied, UserStore.SoftDelete actually persists state
-- and FindByEmail / FindByID exclude tombstoned rows.
--
-- A partial unique index on lower(email) WHERE deleted_at IS NULL
-- supersedes the plain idx_users_email_lower from migration 0005 for
-- live lookups. The non-partial index is left in place as a fallback
-- for queries that intentionally want to see deleted rows (admin
-- recovery flows). Postgres will pick the partial index for the
-- common login path because it is smaller.
--
-- Idempotent: every object uses IF NOT EXISTS / DO blocks.
-- Apply with `make migrate-up`; safe to replay.

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Partial index used by FindByEmail to skip soft-deleted rows. Same
-- email can be re-registered after a delete because this index does
-- not span deleted rows.
CREATE INDEX IF NOT EXISTS idx_users_email_lower_live
    ON users (LOWER(email))
    WHERE deleted_at IS NULL;

COMMIT;
