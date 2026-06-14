package db

const ddlReadingHistory = `
CREATE TABLE IF NOT EXISTS post_reads (
  user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id   UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  read_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, post_id)
);
CREATE INDEX IF NOT EXISTS idx_post_reads_user ON post_reads(user_id, read_at DESC);`
