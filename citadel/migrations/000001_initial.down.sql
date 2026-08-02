-- CITADEL v1.0.0 — Initial Schema (rollback)

BEGIN;

DROP TABLE IF EXISTS rate_counters;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS anchors;
DROP TABLE IF EXISTS marshal_decisions;
DROP TABLE IF EXISTS worm_entries;
DROP SEQUENCE IF EXISTS worm_seq;

COMMIT;
