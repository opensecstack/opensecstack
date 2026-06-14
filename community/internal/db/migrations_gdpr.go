package db

const ddlDeletionRequests = `
CREATE TABLE IF NOT EXISTS deletion_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processed','cancelled')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    scheduled_for TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days',
    processed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_deletion_requests_pending ON deletion_requests(user_id) WHERE status = 'pending';`
