package db

const ddlMutes = `
CREATE TABLE IF NOT EXISTS user_mutes (
  muter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  muted_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (muter_id, muted_id),
  CHECK (muter_id != muted_id)
);
CREATE INDEX IF NOT EXISTS idx_user_mutes_muter_id ON user_mutes(muter_id);`
