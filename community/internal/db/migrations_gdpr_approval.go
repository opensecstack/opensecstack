package db

// ddlDeletionApproval adds a real two-person approval gate to GDPR account
// deletion: an admin distinct from the requesting user must explicitly
// approve a pending deletion_requests row (transitioning it to 'approved')
// before either the scheduler's unattended sweep (scheduler.go's
// processDeletions) or an admin's immediate POST /.../process will ever
// actually execute DELETE FROM users for it. See
// internal/api/handlers/gdpr.go's AdminApproveDeletion and
// internal/citadel/governance.go for the CITADEL MARSHAL evaluation that
// additionally gates the DELETE itself.
const ddlDeletionApproval = `
ALTER TABLE deletion_requests ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE deletion_requests ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE deletion_requests DROP CONSTRAINT IF EXISTS deletion_requests_status_check;
ALTER TABLE deletion_requests ADD CONSTRAINT deletion_requests_status_check
    CHECK (status IN ('pending','approved','processed','cancelled'));`
