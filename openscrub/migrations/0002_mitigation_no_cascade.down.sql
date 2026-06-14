-- Reverse 0002. Best-effort: rows whose rule_id is NULL (because the
-- parent rule was deleted under SET NULL) cannot be reattached, so they
-- are dropped — there is no safe value to restore.

DELETE FROM mitigations WHERE rule_id IS NULL;

ALTER TABLE mitigations DROP CONSTRAINT IF EXISTS mitigations_rule_id_fkey;
ALTER TABLE mitigations ALTER COLUMN rule_id SET NOT NULL;
ALTER TABLE mitigations
    ADD CONSTRAINT mitigations_rule_id_fkey
    FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE;

DROP INDEX IF EXISTS idx_mitigations_state_started;
DROP INDEX IF EXISTS idx_mitigations_emitted_started;

ALTER TABLE mitigations DROP COLUMN IF EXISTS sent_at;
ALTER TABLE mitigations DROP COLUMN IF EXISTS last_error;
ALTER TABLE mitigations DROP COLUMN IF EXISTS attempts;
ALTER TABLE mitigations DROP COLUMN IF EXISTS state;
ALTER TABLE mitigations DROP COLUMN IF EXISTS rule_source;
ALTER TABLE mitigations DROP COLUMN IF EXISTS rule_type;
ALTER TABLE mitigations DROP COLUMN IF EXISTS rule_cidr;
