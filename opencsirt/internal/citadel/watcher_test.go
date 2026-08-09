package citadel

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

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
