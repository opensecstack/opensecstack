-- Two-person-rule (Separation of Duties) pending actions.
--
-- An Operator proposes a governed incident-response action; it is stored
-- here as 'pending' until a SECOND, distinct authenticated user (the
-- Verifier) approves or rejects it. On approval, CITADEL MARSHAL is
-- evaluated with both real identities and the row transitions to
-- 'approved' (action_id points at the resulting incident_actions row),
-- 'refused' (MARSHAL REFUSE), or 'blocked' (MARSHAL HARD_STOP). On
-- rejection it transitions straight to 'rejected' without ever reaching
-- CITADEL.
--
-- operator_user_id/verifier_user_id are sinauth UUIDs (stored as VARCHAR,
-- consistent with the rest of this schema's VARCHAR ID convention — see
-- 001_initial.sql) captured from two separate authenticated HTTP requests,
-- never from client-supplied request bodies.

CREATE TABLE pending_actions (
    id VARCHAR(50) PRIMARY KEY,
    incident_id VARCHAR(50) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type VARCHAR(20) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence JSONB,
    operator_user_id VARCHAR(100) NOT NULL,
    operator_role VARCHAR(20) NOT NULL DEFAULT '',
    verifier_user_id VARCHAR(100) NOT NULL DEFAULT '',
    verifier_role VARCHAR(20) NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected','refused','blocked')),
    marshal_decision VARCHAR(20) NOT NULL DEFAULT '',
    worm_entry_id VARCHAR(255) NOT NULL DEFAULT '',
    action_id VARCHAR(50) NOT NULL DEFAULT '',
    reasons JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    -- A second person, cryptographically: the operator can never also be
    -- the verifier for the same proposal. Belt-and-braces alongside the
    -- application-level ErrSelfApproval check in incident.Service.
    CHECK (verifier_user_id = '' OR verifier_user_id <> operator_user_id)
);

CREATE INDEX idx_pending_actions_incident_id ON pending_actions(incident_id);
CREATE INDEX idx_pending_actions_status ON pending_actions(status);
