-- 0003_mitigation_start_counters — capture the global drop counters at
-- mitigation start so the watcher can emit a best-effort
-- (end - start) delta as `packets_dropped` / `bytes_dropped`.
--
-- BLOCKER 1 follow-up: migration 0002 added the snapshot + state machine
-- columns but no production code was inserting mitigation rows. The new
-- rules.MitigationLifecycle inserts a row on rule creation and finalizes
-- it on rule delete / TTL expiry. Because the v1.0.0 BPF data plane only
-- exposes *global* drop counters (no per-rule counter map yet — that
-- ships in v1.1 alongside migration 0004), the lifecycle records the
-- global counter at start, again at end, and writes the delta.
--
-- Caveat (documented in internal/rules/mitigation_lifecycle.go): when
-- multiple rules are active concurrently the per-rule split is a coarse
-- attribution at best. The CITADEL event is still WORM-correct (it
-- carries a real, non-zero observed window) but ops should treat the
-- counter as "lower bound traffic dropped during this rule's lifetime"
-- not "traffic this specific rule dropped". v1.1 adds a per-rule
-- PERCPU_HASH map keyed by rule_id and these columns become exact.
--
-- Both columns default to 0 so existing rows (legacy + restart-recovered)
-- read back as zero rather than NULL.

ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS start_packets_dropped BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS start_bytes_dropped   BIGINT NOT NULL DEFAULT 0;
