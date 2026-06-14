-- sinauth: social OAuth identity columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_id TEXT UNIQUE;

CREATE INDEX IF NOT EXISTS users_google_id_idx ON users (google_id);
CREATE INDEX IF NOT EXISTS users_github_id_idx ON users (github_id);
