package handlers

// White-box test for recordAudit, the unexported helper audit.go exposes to
// other handlers (pin.go, deactivate.go, etc.) for writing an audit_log row.
// It lives here in package handlers (not handlers_test) because recordAudit
// itself has no exported surface — the only way to observe it from outside
// the package is indirectly, through a handler that calls it.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRecordAudit_InsertsRow(t *testing.T) {
	pool := NewTestDBPool(t)

	username := "auditor_" + RandomSuffix()
	var actorID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role) VALUES ($1,$1,'admin') RETURNING id`,
		username,
	).Scan(&actorID); err != nil {
		t.Fatalf("insert actor: %v", err)
	}
	CleanupUserByUsername(t, pool, username)

	recordAudit(context.Background(), pool, actorID, "test_action", "post", "target-123", "a note")

	var action, targetType, targetID, note string
	err := pool.QueryRow(context.Background(),
		`SELECT action, target_type, target_id, note FROM audit_log WHERE actor_id=$1 AND action='test_action'`,
		actorID,
	).Scan(&action, &targetType, &targetID, &note)
	if err != nil {
		t.Fatalf("expected recordAudit to insert a row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE actor_id=$1`, actorID)
	})

	if action != "test_action" || targetType != "post" || targetID != "target-123" || note != "a note" {
		t.Errorf("unexpected audit row: action=%q target_type=%q target_id=%q note=%q",
			action, targetType, targetID, note)
	}
}

// recordAudit swallows Exec errors (best-effort logging) — verify it does not
// panic or block when the pool is unreachable.
func TestRecordAudit_DBError_DoesNotPanic(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)

	recordAudit(context.Background(), pool, "actor-id", "action", "type", "target", "note")
}
