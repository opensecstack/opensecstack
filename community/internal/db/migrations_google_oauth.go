package db

const ddlGoogleOAuth = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE;
`
