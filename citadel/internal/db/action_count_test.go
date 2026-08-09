package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestActionCount_QueryErrorIsWrapped confirms ActionCount propagates a real
// query failure (here: an unreachable database) wrapped with "db: action
// count:" context rather than swallowing it or returning a misleading
// zero-with-nil-error result. AUGUR rule_02 relies on this count for a
// rate-limit decision — silently returning 0 on a DB outage would fail open
// (let an action through that should have been rate-limited), so the error
// must surface to the caller instead.
func TestActionCount_QueryErrorIsWrapped(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	d := &DB{Pool: pool}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := d.ActionCount(ctx, "user-1", time.Hour)
	if err == nil {
		t.Fatal("expected error querying an unreachable database")
	}
	if count != 0 {
		t.Errorf("expected count=0 on error, got %d", count)
	}
	if !strings.Contains(err.Error(), "db: action count:") {
		t.Errorf("expected wrapped 'db: action count:' error, got: %v", err)
	}
}
