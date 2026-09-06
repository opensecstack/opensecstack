-- CITADEL — drop the Compliance Evidence table (rollback)

BEGIN;

DROP TABLE IF EXISTS compliance_evidence;

COMMIT;
