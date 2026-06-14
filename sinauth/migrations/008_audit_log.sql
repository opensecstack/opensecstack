-- sinauth: audit log for auth events
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT NOT NULL,  -- login.success, login.failure, token.issued, client.created, etc.
    actor       TEXT,           -- username or client_id
    client_id   TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_actor_idx   ON audit_log (actor);
CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_type_idx    ON audit_log (event_type);
