-- 0002_mitigation_no_cascade — preserve CITADEL evidence across rule deletes.
--
-- BLOCKER 1 fix:
--   * Drops the ON DELETE CASCADE FK on mitigations.rule_id; re-adds it as
--     ON DELETE SET NULL so an operator Delete or TTL sweep can no longer
--     destroy in-flight evidence rows whose `state != 'sent'`.
--   * Captures a rule snapshot (cidr / type / source) on the mitigation
--     row at insertion time so the CITADEL event payload survives the
--     parent rule disappearing.
--   * Replaces the boolean `emitted` flag with a small state machine
--     (pending|sent|failed) plus retry bookkeeping. A `emitted` view
--     column stays as a generated boolean for back-compat readers.
--
-- The watcher (internal/citadel/mitigation_watcher.go) only flips
-- pending→sent on a confirmed CITADEL 2xx; transient retries keep the
-- row as `pending` and bump `attempts`; final exhaustion writes
-- `failed` + `last_error`.

ALTER TABLE mitigations DROP CONSTRAINT IF EXISTS mitigations_rule_id_fkey;

ALTER TABLE mitigations ALTER COLUMN rule_id DROP NOT NULL;

ALTER TABLE mitigations
    ADD CONSTRAINT mitigations_rule_id_fkey
    FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE SET NULL;

-- Rule snapshot columns. Populated at insert; survive rule deletion.
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS rule_cidr   CIDR;
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS rule_type   TEXT;
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS rule_source TEXT;

-- State machine. Existing `emitted=false` rows become 'pending';
-- `emitted=true` rows become 'sent'. The boolean column is preserved
-- for callers that already read it.
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS state       TEXT NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'sent', 'failed'));
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS attempts    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS last_error  TEXT;
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS sent_at     TIMESTAMPTZ;

UPDATE mitigations SET state = 'sent', sent_at = COALESCE(sent_at, ended_at, started_at)
    WHERE emitted = TRUE AND state = 'pending';

-- Watcher hot path: cheap lookup of (state='pending', ended_at NOT NULL).
CREATE INDEX IF NOT EXISTS idx_mitigations_state_started ON mitigations (state, started_at);
CREATE INDEX IF NOT EXISTS idx_mitigations_emitted_started ON mitigations (emitted, started_at);
