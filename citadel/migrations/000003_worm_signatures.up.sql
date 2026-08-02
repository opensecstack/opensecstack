-- CITADEL — persist Operator/Verifier Ed25519 signatures on the WORM record
-- itself, so the immutable audit chain carries the non-repudiation evidence
-- (IEEE paper Definition 2), not just MARSHAL's in-memory decision.

BEGIN;

ALTER TABLE worm_entries
    ADD COLUMN IF NOT EXISTS sig_operator TEXT,
    ADD COLUMN IF NOT EXISTS sig_verifier TEXT;

COMMIT;
