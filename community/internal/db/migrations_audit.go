package db

import (
	"context"

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

func LogAudit(ctx context.Context, pool *pgxpool.Pool, actorID, action, targetType, targetID, note string) {
	pool.Exec(ctx,
		`INSERT INTO audit_log (actor_id, action, target_type, target_id, note) VALUES ($1,$2,$3,$4,$5)`,
		actorID, action, targetType, targetID, note,
	)
}
