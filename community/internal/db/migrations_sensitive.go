package db

const ddlSensitive = `
ALTER TABLE posts ADD COLUMN IF NOT EXISTS sensitive BOOLEAN NOT NULL DEFAULT false;`
