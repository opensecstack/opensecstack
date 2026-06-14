package db

const ddlEmailNotifPrefs = `
ALTER TABLE notification_preferences
  ADD COLUMN IF NOT EXISTS email_follows   BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS email_comments  BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS email_reactions BOOLEAN NOT NULL DEFAULT false;
`
