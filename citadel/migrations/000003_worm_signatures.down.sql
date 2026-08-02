-- CITADEL — drop Operator/Verifier Ed25519 signature columns from worm_entries

BEGIN;

ALTER TABLE worm_entries
    DROP COLUMN IF EXISTS sig_operator,
    DROP COLUMN IF EXISTS sig_verifier;

COMMIT;
