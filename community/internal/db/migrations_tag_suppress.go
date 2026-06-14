package db

const ddlTagSuppressions = `
CREATE TABLE IF NOT EXISTS tag_suppressions (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag_id  UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, tag_id)
);`
