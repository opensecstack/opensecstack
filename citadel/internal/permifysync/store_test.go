package permifysync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// unreachablePool returns a lazily-connecting pool aimed at a port that
// actively refuses connections, so calls against it fail fast with a real
// connection error rather than hanging until a context deadline.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestNewPgSnapshotStore_ImplementsSnapshotStore(t *testing.T) {
	var _ SnapshotStore = NewPgSnapshotStore(unreachablePool(t))
}

// TestReplaceSnapshot_BeginTxErrorIsWrapped confirms ReplaceSnapshot
// propagates a real transaction-begin failure instead of silently returning
// success — a "successful" replace that never wrote anything would silently
// desync the in-memory snapshot from the persisted one.
func TestReplaceSnapshot_BeginTxErrorIsWrapped(t *testing.T) {
	s := NewPgSnapshotStore(unreachablePool(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.ReplaceSnapshot(ctx, map[RoleAction]bool{{Role: "admin", ActionType: "X"}: true})
	if err == nil {
		t.Fatal("expected error replacing snapshot against an unreachable database")
	}
	if !strings.Contains(err.Error(), "permifysync: begin tx:") {
		t.Errorf("expected wrapped 'permifysync: begin tx:' error, got: %v", err)
	}
}

// TestReplaceSnapshot_EmptyRowsStillAttemptsClear confirms ReplaceSnapshot
// still begins a transaction (to clear the table) even when rows is empty —
// an empty sync result is a legitimate state (see PermifyFetcher's doc
// comment) that must still replace whatever was persisted before, not
// short-circuit into a silent no-op.
func TestReplaceSnapshot_EmptyRowsStillAttemptsClear(t *testing.T) {
	s := NewPgSnapshotStore(unreachablePool(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.ReplaceSnapshot(ctx, map[RoleAction]bool{})
	if err == nil {
		t.Fatal("expected error: even an empty-rows replace must touch the DB to clear stale data")
	}
	if !strings.Contains(err.Error(), "permifysync: begin tx:") {
		t.Errorf("expected wrapped 'permifysync: begin tx:' error, got: %v", err)
	}
}

// TestLoadSnapshot_QueryErrorIsWrapped confirms LoadSnapshot propagates a
// real query failure — Syncer.LoadInitial treats an error as "start from an
// empty snapshot" (logged as a warning), so this must be a real error, not
// silently returned as an empty-but-successful map that would be
// indistinguishable from "nothing has ever synced".
func TestLoadSnapshot_QueryErrorIsWrapped(t *testing.T) {
	s := NewPgSnapshotStore(unreachablePool(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := s.LoadSnapshot(ctx)
	if err == nil {
		t.Fatal("expected error loading snapshot from an unreachable database")
	}
	if data != nil {
		t.Errorf("expected nil data on error, got %v", data)
	}
	if !strings.Contains(err.Error(), "permifysync: load snapshot:") {
		t.Errorf("expected wrapped 'permifysync: load snapshot:' error, got: %v", err)
	}
}
