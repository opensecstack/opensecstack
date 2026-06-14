package db

func init() {
	migrations = append(migrations,
		// Remove the restrictive type CHECK so new notification types can be added without re-migrating.
		`ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_type_check`,

		// Add space_id column for space-related notifications.
		`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS space_id UUID REFERENCES spaces(id) ON DELETE CASCADE`,

		// Track per-user per-channel last-read timestamp for unread count badges.
		`CREATE TABLE IF NOT EXISTS channel_last_read (
			user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			channel_id   UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
			last_read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (user_id, channel_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_channel_last_read_user ON channel_last_read(user_id)`,
	)
}
