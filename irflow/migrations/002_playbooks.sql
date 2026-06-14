-- Playbooks and their execution history.
--
-- Playbook.Trigger is small structured metadata stored as JSONB so it can be
-- queried with ->/? operators (e.g. filter by event_type).
-- Playbook.Steps is an ordered list of step definitions stored as JSONB.
-- Execution.StepResults is the time-ordered log of what ran, stored as JSONB.

CREATE TABLE playbooks (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    version VARCHAR(50) NOT NULL DEFAULT '1.0',
    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','active','archived')),
    trigger JSONB NOT NULL DEFAULT '{}'::jsonb,
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by VARCHAR(100) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE playbook_executions (
    id VARCHAR(50) PRIMARY KEY,
    playbook_id VARCHAR(50) NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    incident_id VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','running','completed','failed','cancelled')),
    current_step VARCHAR(100) NOT NULL DEFAULT '',
    step_results JSONB NOT NULL DEFAULT '[]'::jsonb,
    error TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_playbooks_status ON playbooks(status);
CREATE INDEX idx_playbooks_trigger_event ON playbooks((trigger->>'event_type'));
CREATE INDEX idx_playbook_executions_playbook_id ON playbook_executions(playbook_id);
CREATE INDEX idx_playbook_executions_incident_id ON playbook_executions(incident_id);
CREATE INDEX idx_playbook_executions_status ON playbook_executions(status);
CREATE INDEX idx_playbook_executions_started_at ON playbook_executions(started_at DESC);
