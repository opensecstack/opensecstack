-- CITADEL — Operator/Verifier Ed25519 signing key registry.
-- See adrs/004-operator-verifier-ed25519-signatures.md.
--
-- Separate from `anchors` (periodic chain-anchor signing, a different key
-- and a different purpose): this table holds per-user public keys used to
-- verify the SigOperator/SigVerifier fields of an individual Kerkese
-- request in Gate 1 (AuthN) and Gate 3 (NDS).

BEGIN;

CREATE TABLE IF NOT EXISTS signing_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     BIGINT      NOT NULL,
    key_id      TEXT        NOT NULL,
    public_key  TEXT        NOT NULL,  -- hex, 64 chars (32-byte Ed25519 public key)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    UNIQUE (user_id, key_id)
);

-- At most one row per user should be "active" (revoked_at IS NULL) at a
-- time; enforced in application code (RegisterKey), not by a DB constraint,
-- so key rotation (register-new, then revoke-old) can proceed in two steps
-- without a transient constraint violation.
CREATE INDEX IF NOT EXISTS idx_signing_keys_active
    ON signing_keys (user_id) WHERE revoked_at IS NULL;

COMMIT;
