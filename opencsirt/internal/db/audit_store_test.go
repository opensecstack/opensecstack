package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// unreachablePool returns a pgx pool configured against a syntactically
// valid but unreachable address. pgxpool.NewWithConfig never dials
// eagerly, so construction always succeeds; the first real query then
// fails fast with a connection error. This exercises each store's real
// default-value logic and error-propagation branches without a live
// Postgres.
func unreachablePool(t *testing.T) *Pool {
	t.Helper()
	pool, err := Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAuditStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewAuditStore(unreachablePool(t))
	a := &AuditEntry{ActorRole: "admin", Action: "test.action"}

	err := s.Insert(context.Background(), a)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	// The defaulting logic runs before the failing Exec call, so it must
	// still have mutated the entry in place.
	if a.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if a.CreatedAt.IsZero() {
		t.Error("Insert did not assign a default CreatedAt before failing")
	}
	if a.Metadata == nil {
		t.Error("Insert did not default nil Metadata to an empty map before failing")
	}
}

func TestAuditStoreInsert_PreservesCallerSuppliedIDAndTimestamp(t *testing.T) {
	s := NewAuditStore(unreachablePool(t))
	id := uuid.New()
	ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &AuditEntry{ID: id, CreatedAt: ts, ActorRole: "admin", Action: "test.action"}

	_ = s.Insert(context.Background(), a)

	if a.ID != id {
		t.Errorf("Insert overwrote caller-supplied ID: got %s want %s", a.ID, id)
	}
	if !a.CreatedAt.Equal(ts) {
		t.Errorf("Insert overwrote caller-supplied CreatedAt: got %s want %s", a.CreatedAt, ts)
	}
}

func TestIOCIngestStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewIOCIngestStore(unreachablePool(t))
	e := &IOCIngestEntry{Source: "threatflow", BundleSHA256: "abc", Count: 3}

	err := s.Insert(context.Background(), e)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if e.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if e.IngestedAt.IsZero() {
		t.Error("Insert did not assign a default IngestedAt before failing")
	}
}

func TestIOCIngestStoreLastForSource_PropagatesError(t *testing.T) {
	s := NewIOCIngestStore(unreachablePool(t))
	_, err := s.LastForSource(context.Background(), "threatflow")
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}
