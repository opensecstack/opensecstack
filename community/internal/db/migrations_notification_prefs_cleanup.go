package db

// ddlNotificationPrefsCleanup consolidates the three legacy opt-in columns
// (comment_email, reaction_email, follow_email) into the canonical email_*
// columns added by ddlEmailNotifPrefs, then drops the duplicates.
// Must run after both ddlNotificationPrefs and ddlEmailNotifPrefs.
//
// Idempotent: migrations re-run on every startup, so the consolidation UPDATE
// is guarded behind a column-existence check — after the first run drops the
// legacy columns, subsequent runs skip the UPDATE instead of erroring on the
// now-missing comment_email/reaction_email/follow_email references.
const ddlNotificationPrefsCleanup = `
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'notification_preferences' AND column_name = 'comment_email'
  ) THEN
    UPDATE notification_preferences SET
      email_comments  = email_comments  OR comment_email,
      email_reactions = email_reactions OR reaction_email,
      email_follows   = email_follows   OR follow_email
    WHERE comment_email OR reaction_email OR follow_email;
  END IF;
END $$;

ALTER TABLE notification_preferences
  DROP COLUMN IF EXISTS comment_email,
  DROP COLUMN IF EXISTS reaction_email,
  DROP COLUMN IF EXISTS follow_email;
`
