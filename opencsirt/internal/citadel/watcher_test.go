package citadel

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

// unreachablePool returns a pgx pool configured against a syntactically
// valid but unreachable address. pgxpool.NewWithConfig never dials
// eagerly, so construction always succeeds; the first real query then
// fails fast with a connection error.
func unreachablePool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestNewWatcher_InitializesInFlightMap(t *testing.T) {
	w := NewWatcher(nil, nil, time.Second, zerolog.Nop())
	if w == nil {
		t.Fatal("NewWatcher returned nil")
	}
	if w.inFlight == nil {
		t.Fatal("inFlight map should be initialized, not nil")
	}
	if len(w.inFlight) != 0 {
		t.Fatalf("inFlight should start empty, got %d entries", len(w.inFlight))
	}
}

func TestWatcher_UntrackRemovesEntry(t *testing.T) {
	w := NewWatcher(nil, nil, time.Second, zerolog.Nop())
	rowID := uuid.New()
	w.inFlight["evt-1"] = rowID

	if _, ok := w.inFlight["evt-1"]; !ok {
		t.Fatal("setup: entry should be present before untrack")
	}

	w.untrack("evt-1")

	if _, ok := w.inFlight["evt-1"]; ok {
		t.Fatal("untrack should have removed the entry")
	}
}

func TestWatcher_UntrackUnknownEventIsNoOp(t *testing.T) {
	w := NewWatcher(nil, nil, time.Second, zerolog.Nop())
	// Must not panic when the event was never tracked.
	w.untrack("does-not-exist")
	if len(w.inFlight) != 0 {
		t.Fatalf("inFlight should remain empty, got %d entries", len(w.inFlight))
	}
}

// TestWatcher_TickOnce_PendingFetchErrorReturnsWithoutPanicking exercises
// the real (previously 0%-covered) tickOnce body: store.Pending fails
// against an unreachable DB, and tickOnce must log and return rather than
// touching client/inFlight state at all.
func TestWatcher_TickOnce_PendingFetchErrorReturnsWithoutPanicking(t *testing.T) {
	pool := unreachablePool(t)
	store := db.NewOutboxStore(pool)
	// client is nil on purpose: if tickOnce pressed on past the Pending
	// error to call w.client.Submit, this would panic.
	w := NewWatcher(store, nil, time.Second, zerolog.Nop())
	w.tickOnce(context.Background())
	if len(w.inFlight) != 0 {
		t.Fatalf("inFlight should remain empty after a Pending fetch error, got %d entries", len(w.inFlight))
	}
}

// TestWatcher_Run_RequeueSendingErrorDoesNotBlockStartup proves Run logs
// (rather than fatally aborting on) a RequeueSending failure and still
// reaches its select loop, honoring context cancellation promptly. This
// covers Run's previously-0%-covered startup path.
func TestWatcher_Run_RequeueSendingErrorDoesNotBlockStartup(t *testing.T) {
	pool := unreachablePool(t)
	store := db.NewOutboxStore(pool)
	client := New("", nil, "", "opencsirt", false, zerolog.Nop()) // apiURL empty; Submit is never reached here anyway
	w := NewWatcher(store, client, 5*time.Millisecond, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Run returned promptly once ctx was done — good.
	case <-time.After(2 * time.Second):
		t.Fatal("Watcher.Run did not return within 2s of context cancellation")
	}
}
