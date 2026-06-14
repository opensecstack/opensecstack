package db

const ddlLock = `
ALTER TABLE posts ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT false;`
