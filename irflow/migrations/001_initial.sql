-- IRFlow initial schema.
--
-- IDs are VARCHAR rather than UUID because the service generates
-- application-level IDs with a readable prefix (inc-, act-, ioc-) that embed
-- a nanosecond timestamp for chronological ordering.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incidents (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity VARCHAR(2) NOT NULL CHECK (severity IN ('P1','P2','P3','P4')),
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    source VARCHAR(20) NOT NULL,
    source_ref VARCHAR(255) NOT NULL DEFAULT '',
    project_id VARCHAR(100) NOT NULL DEFAULT '',
    commander_id VARCHAR(100) NOT NULL DEFAULT '',
    lead_id VARCHAR(100) NOT NULL DEFAULT '',
    root_cause TEXT NOT NULL DEFAULT '',
    corrective_action TEXT NOT NULL DEFAULT '',
    worm_entry_id VARCHAR(255) NOT NULL DEFAULT '',
    nis2_notify_required BOOLEAN NOT NULL DEFAULT false,
    nis2_notified_at TIMESTAMPTZ,
    contained_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incident_actions (
    id VARCHAR(50) PRIMARY KEY,
    incident_id VARCHAR(50) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type VARCHAR(20) NOT NULL,
    operator_id VARCHAR(100) NOT NULL,
    verifier_id VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence JSONB,
    marshal_decision VARCHAR(20) NOT NULL DEFAULT '',
    worm_entry_id VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ioc_enrichments (
    id VARCHAR(50) PRIMARY KEY,
    incident_id VARCHAR(50) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_type VARCHAR(20) NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    source VARCHAR(50) NOT NULL DEFAULT '',
    stix_bundle JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE timeline_entries (
    id VARCHAR(50) PRIMARY KEY,
    incident_id VARCHAR(50) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    entry_type VARCHAR(20) NOT NULL,
    actor_id VARCHAR(100) NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_source ON incidents(source);
CREATE INDEX idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX idx_incident_actions_incident_id ON incident_actions(incident_id);
CREATE INDEX idx_ioc_enrichments_incident_id ON ioc_enrichments(incident_id);
CREATE INDEX idx_timeline_entries_incident_id ON timeline_entries(incident_id);
