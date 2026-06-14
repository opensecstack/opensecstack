package db

const ddlSchedule = `
ALTER TABLE posts DROP CONSTRAINT IF EXISTS posts_state_check;
ALTER TABLE posts ADD CONSTRAINT posts_state_check CHECK (state IN ('draft','published','scheduled'));
ALTER TABLE posts ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;`
