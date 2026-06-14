package db

const ddlTagAliases = `
CREATE TABLE IF NOT EXISTS tag_aliases (
    alias  TEXT PRIMARY KEY,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tag_aliases_tag_id ON tag_aliases(tag_id);`
