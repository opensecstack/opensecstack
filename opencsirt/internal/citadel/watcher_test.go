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

// waitForInFlightRemoved polls w.inFlight until eventID is gone or the
// timeout elapses. consumeConfirmations mutates the map on its own
// goroutine, so a direct read right after sending on the channel would race.
func waitForInFlightRemoved(t *testing.T, w *Watcher, eventID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		_, ok := w.inFlight[eventID]
		w.mu.Unlock()
		if !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("inFlight[%q] was not removed within %s", eventID, timeout)
}

// TestWatcher_ConsumeConfirmations_DeliveredMarksSentAndUntracks exercises
// consumeConfirmations' tracked+Delivered branch (store.MarkSent). The
// unreachable-DB pool means MarkSent itself errors, but that error is
// intentionally discarded by consumeConfirmations (`_ = w.store.MarkSent`),
// so what this test verifies is the branch is taken and the event is
// untracked regardless of the store call's outcome.
func TestWatcher_ConsumeConfirmations_DeliveredMarksSentAndUntracks(t *testing.T) {
	pool := unreachablePool(t)
	store := db.NewOutboxStore(pool)
	client := New("", nil, "", "opencsirt", true, zerolog.Nop())
	w := NewWatcher(store, client, time.Second, zerolog.Nop())

	rowID := uuid.New()
	w.inFlight["evt-delivered"] = rowID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.consumeConfirmations(ctx)

	client.confirms <- Confirmation{EventID: "evt-delivered", Outcome: SubmitDelivered}
	waitForInFlightRemoved(t, w, "evt-delivered", 2*time.Second)
}

// TestWatcher_ConsumeConfirmations_DroppedMarksFailedAndUntracks exercises
// the tracked+Dropped branch (store.MarkFailed), including the
// conf.Err != nil message-selection line.
func TestWatcher_ConsumeConfirmations_DroppedMarksFailedAndUntracks(t *testing.T) {
	pool := unreachablePool(t)
	store := db.NewOutboxStore(pool)
	client := New("", nil, "", "opencsirt", true, zerolog.Nop())
	w := NewWatcher(store, client, time.Second, zerolog.Nop())

	rowID := uuid.New()
	w.inFlight["evt-dropped"] = rowID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.consumeConfirmations(ctx)

	client.confirms <- Confirmation{EventID: "evt-dropped", Outcome: SubmitDropped, Err: context.DeadlineExceeded}
	waitForInFlightRemoved(t, w, "evt-dropped", 2*time.Second)
}

// TestWatcher_ConsumeConfirmations_UntrackedEventIsSkipped proves
// consumeConfirmations' `if !ok { continue }` branch: a confirmation for an
// event this watcher never tracked must not touch the store or panic.
func TestWatcher_ConsumeConfirmations_UntrackedEventIsSkipped(t *testing.T) {
	pool := unreachablePool(t)
	store := db.NewOutboxStore(pool)
	client := New("", nil, "", "opencsirt", true, zerolog.Nop())
	w := NewWatcher(store, client, time.Second, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		w.consumeConfirmations(ctx)
		close(done)
	}()

	client.confirms <- Confirmation{EventID: "never-tracked", Outcome: SubmitDelivered}

	// Send a second, tracked confirmation and wait for it to be processed —
	// this proves the goroutine kept running (didn't panic) past the
	// untracked one.
	rowID := uuid.New()
	w.mu.Lock()
	w.inFlight["evt-after"] = rowID
	w.mu.Unlock()
	client.confirms <- Confirmation{EventID: "evt-after", Outcome: SubmitDelivered}
	waitForInFlightRemoved(t, w, "evt-after", 2*time.Second)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeConfirmations did not stop after ctx cancellation")
	}
}

// TestWatcher_ConsumeConfirmations_StopsOnContextDone proves
// consumeConfirmations' top-level ctx.Done() branch returns promptly even
// with no confirmations ever arriving.
func TestWatcher_ConsumeConfirmations_StopsOnContextDone(t *testing.T) {
	pool := unreachablePool(t)
	store := db.NewOutboxStore(pool)
	client := New("", nil, "", "opencsirt", true, zerolog.Nop())
	w := NewWatcher(store, client, time.Second, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.consumeConfirmations(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeConfirmations did not stop promptly on ctx cancellation")
	}
}
