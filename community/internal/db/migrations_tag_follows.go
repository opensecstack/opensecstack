package db

const ddlTagFollows = `
CREATE TABLE IF NOT EXISTS tag_follows (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag_id  UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_tag_follows_user_id ON tag_follows(user_id);`
