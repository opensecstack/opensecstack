-- CITADEL — local snapshot of Permify-derived role -> action_type coverage,
-- for MARSHAL Gate 2 (AuthZ). Gate 2 must never make a live synchronous call
-- to Permify per-request (it runs in the hot path of every governed action
-- across the ecosystem at ~microsecond latency); instead it reads this
-- table's in-memory copy, refreshed on an interval by
-- internal/permifysync.Syncer. See adrs/007-permify-gate2-snapshot.md.
--
-- As of this migration, sinauth's Permify schema (sinauth/permify/schema.perm)
-- models organization/group/client_role membership, not CITADEL's governed
-- action-type vocabulary (API_SCAN_INITIATE, INCIDENT_CREATE, ...) — so this
-- table is expected to sync EMPTY until the schema is extended in a later
-- phase. Gate 2's existing rbacMap check remains the unconditionally
-- enforced safety net; a row here only ever adds a soft WARN-until-enabled
-- signal on top of it (internal/marshal/marshal.go's gate2AuthZ).

BEGIN;

CREATE TABLE IF NOT EXISTS permify_role_action_snapshot (
    role        TEXT        NOT NULL,
    action_type TEXT        NOT NULL,
    allowed     BOOLEAN     NOT NULL,
    synced_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role, action_type)
);

COMMIT;
