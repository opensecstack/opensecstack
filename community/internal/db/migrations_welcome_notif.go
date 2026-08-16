package db

// This used to re-add notifications_type_check with a fixed 5-value
// whitelist right after dropping it, which broke Migrate()'s full replay
// (no tracking table — every DDL string re-runs on every process start)
// as soon as any row existed with a newer notification type (e.g.
// space_joined): ADD CONSTRAINT validates against existing rows
// immediately, so it failed here even though migrations_notifications_v2.go
// deliberately drops the same constraint later in the list "so new
// notification types can be added without re-migrating". Keeping only the
// DROP (idempotent, harmless to replay) matches that documented intent —
// the type column is meant to stay unconstrained.
const ddlWelcomeNotification = `
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_type_check;`
