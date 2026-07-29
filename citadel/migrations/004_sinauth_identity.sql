-- CITADEL — adopt sinauth's UUID as the canonical user identity, and drop
-- the local `sessions` table: nothing in the ecosystem ever wrote to it, so
-- Gate 1 (AuthN) could never pass for a real request. AuthN now verifies a
-- sinauth-issued bearer token directly (see internal/auth.SinauthVerifier)
-- instead of a disconnected local session store.
-- See adrs/005-sinauth-identity-bridge.md.

BEGIN;

DROP TABLE IF EXISTS sessions;

ALTER TABLE rate_counters ALTER COLUMN user_id TYPE TEXT USING user_id::TEXT;
ALTER TABLE signing_keys  ALTER COLUMN user_id TYPE TEXT USING user_id::TEXT;

COMMIT;
