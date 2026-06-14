package db

const ddlPostRevisions = `
CREATE TABLE IF NOT EXISTS post_revisions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    revised_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_post_revisions_post_id ON post_revisions(post_id, revised_at DESC);`
