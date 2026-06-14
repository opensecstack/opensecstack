package db

const ddlSinauthOAuth = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS sinauth_id TEXT UNIQUE;
`
