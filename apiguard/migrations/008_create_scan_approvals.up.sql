-- Real two-person approval for scan initiation (Separation of Duties).
--
-- A scan created while citadel.require_approval is enabled starts in the new
-- 'pending_approval' status instead of launching immediately. A genuine,
-- distinct second authenticated user must call
-- POST /api/v1/scans/{id}/approve (or /reject) before it runs — see
-- internal/api/handlers/scans.go's Approve/Reject handlers.
--
-- Note: PostgreSQL allows adding an enum value inside a transaction (PG12+)
-- as long as the new value is not referenced within that same transaction,
-- which holds here — this migration only adds the value, it does not use it.
ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'pending_approval';

CREATE TABLE IF NOT EXISTS scan_approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,

    -- The real sinauth UserID of the Operator who requested the scan.
    requested_by TEXT NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending | approved | rejected

    -- The real sinauth UserID of the Verifier who approved or rejected the
    -- request — always distinct from requested_by; enforced at the API layer
    -- (403 on same-identity attempts), never at the DB layer alone.
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    decision_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_approvals_scan_id ON scan_approvals(scan_id);
CREATE INDEX idx_scan_approvals_status ON scan_approvals(status);
