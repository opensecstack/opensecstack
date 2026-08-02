-- CITADEL — drop the Permify role/action Gate 2 snapshot table (rollback)

BEGIN;

DROP TABLE IF EXISTS permify_role_action_snapshot;

COMMIT;
