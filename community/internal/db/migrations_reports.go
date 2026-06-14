package db

const ddlReports = `
CREATE TABLE IF NOT EXISTS reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id     UUID REFERENCES posts(id) ON DELETE CASCADE,
    comment_id  UUID REFERENCES comments(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL CHECK (reason IN ('spam','harassment','off_topic','misinformation','other')),
    note        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN ('pending','resolved','dismissed')) DEFAULT 'pending',
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (post_id IS NOT NULL AND comment_id IS NULL) OR
        (post_id IS NULL AND comment_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, created_at DESC);`
