package db

const ddlBroadcasts = `
CREATE TABLE IF NOT EXISTS broadcasts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    body       TEXT NOT NULL,
    link_url   TEXT,
    active     BOOLEAN NOT NULL DEFAULT true,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_broadcasts_active ON broadcasts(active, created_at DESC);`
