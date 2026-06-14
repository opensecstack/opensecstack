-- VG-AUDIT: immutable audit trail for state-changing API calls.
CREATE TABLE IF NOT EXISTS audit_events (
  id          UUID PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor       TEXT,
  role        TEXT,
  action      TEXT NOT NULL,
  target_type TEXT,
  target_id   TEXT,
  outcome     TEXT NOT NULL,
  status_code INT,
  request_id  TEXT,
  remote_ip   INET,
  metadata    JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts        ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_ts  ON audit_events (actor, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action_ts ON audit_events (action, ts DESC);
