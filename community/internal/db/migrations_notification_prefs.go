package db

const ddlNotificationPrefs = `
CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id           UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    comment_email     BOOLEAN NOT NULL DEFAULT true,
    reaction_email    BOOLEAN NOT NULL DEFAULT false,
    follow_email      BOOLEAN NOT NULL DEFAULT true,
    mention_email     BOOLEAN NOT NULL DEFAULT true,
    digest_enabled    BOOLEAN NOT NULL DEFAULT false,
    digest_frequency  TEXT NOT NULL DEFAULT 'weekly' CHECK (digest_frequency IN ('weekly', 'daily')),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_digest_at TIMESTAMPTZ;`
