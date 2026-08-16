package db

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

const ddlAuditLog = `
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);`

// LogAudit inserts an audit_log row. actorID may be empty for actions with
// no live human actor (e.g. a background scheduler task) — audit_log.actor_id
// is a nullable FK (ON DELETE SET NULL), so an empty actorID is inserted as
// SQL NULL rather than attempting to parse "" as a UUID, which would fail.
func LogAudit(ctx context.Context, pool *pgxpool.Pool, actorID, action, targetType, targetID, note string) {
	var actor any
	if actorID != "" {
		actor = actorID
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_log (actor_id, action, target_type, target_id, note) VALUES ($1,$2,$3,$4,$5)`,
		actor, action, targetType, targetID, note,
	); err != nil {
		slog.Error("LogAudit: insert failed", "action", action, "target_type", targetType, "target_id", targetID, "err", err)
	}
}
