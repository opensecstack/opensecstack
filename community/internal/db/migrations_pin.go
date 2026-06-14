package db

const ddlPin = `
ALTER TABLE posts ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_posts_pinned ON posts(pinned) WHERE pinned = true;`
