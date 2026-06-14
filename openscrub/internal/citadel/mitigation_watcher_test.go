package citadel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// fakeStore implements MitigationStore with an in-memory state machine
// so the tests can assert the exact transitions the BLOCKER 2 fix
// promises (pending → sending → sent | failed). Mirrors what the
// Postgres-backed store does, minus the SQL.
type fakeStore struct {
	mu      sync.Mutex
	pending []MitigationRecord
	state   map[uuid.UUID]string
	errors  map[uuid.UUID]string
	sent    map[uuid.UUID]bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		state:  map[uuid.UUID]string{},
		errors: map[uuid.UUID]string{},
		sent:   map[uuid.UUID]bool{},
	}
}

func (f *fakeStore) PendingForEmit(_ context.Context, _ time.Duration, _ int) ([]MitigationRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]MitigationRecord, 0)
	for _, r := range f.pending {
		if f.state[r.ID] == "" {
			f.state[r.ID] = "pending"
		}
		if f.state[r.ID] == "pending" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeStore) MarkSending(_ context.Context, id uuid.UUID, eventID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[id] = "pending"
	if eventID != "" {
		f.errors[id] = "in_flight:" + eventID
	}
	return nil
}

func (f *fakeStore) MarkSent(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[id] = "sent"
	f.sent[id] = true
	delete(f.errors, id)
	return nil
}

func (f *fakeStore) MarkFailed(_ context.Context, id uuid.UUID, lastErr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[id] = "failed"
	f.errors[id] = lastErr
	return nil
}

func (f *fakeStore) MarkEmitted(ctx context.Context, id uuid.UUID) error {
	return f.MarkSent(ctx, id)
}

func (f *fakeStore) LookupByEventID(_ context.Context, eventID string) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := "in_flight:" + eventID
	for id, e := range f.errors {
		if e == want {
			return id, nil
		}
	}
	return uuid.Nil, nil
}

func (f *fakeStore) getState(id uuid.UUID) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state[id]
}

func (f *fakeStore) wasSent(id uuid.UUID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[id]
}

// stubRecord builds a fully-populated mitigation record for the watcher.
func stubRecord() MitigationRecord {
	return MitigationRecord{
		ID:             uuid.New(),
		RuleID:         uuid.New(),
		StartedAt:      time.Now().Add(-30 * time.Second),
		EndedAt:        time.Now(),
		PacketsDropped: 100,
		BytesDropped:   1500,
		Rule: RuleSummary{
			ID: uuid.New().String(), CIDR: "203.0.113.0/24",
			Type: "blocklist", Source: "operator",
		},
	}
}

// TestWatcherDoesNotMarkSentOnQueuedSubmit asserts the central BLOCKER 2
// invariant: a transient (5xx) failure must keep the row 'pending'.
// MarkSent only fires once the retry loop confirms delivery.
func TestWatcherDoesNotMarkSentOnQueuedSubmit(t *testing.T) {
	// Server that always returns 503 — every Submit goes to the retry
	// queue. We never let the retry loop run, so the confirmation
	// channel stays empty.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: time.Second}, zerolog.Nop())
	store := newFakeStore()
	rec := stubRecord()
	store.pending = []MitigationRecord{rec}

	w := NewWatcher(c, store, WatcherConfig{NodeName: "n"}, zerolog.Nop())
	if err := w.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if store.wasSent(rec.ID) {
		t.Fatal("row was MarkSent on a queued submit — BLOCKER 2 regression")
	}
	if got := store.getState(rec.ID); got != "pending" {
		t.Fatalf("state = %q, want pending", got)
	}
}

// TestWatcherMarksFailedOnRetryExhaustion drives the full retry loop
// until MaxRetries is hit and asserts the watcher's confirmation
// drainer flips the row to 'failed' (not 'sent').
func TestWatcherMarksFailedOnRetryExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := New(Config{
		BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: 100 * time.Millisecond,
		MaxRetries: 1, RetryBaseDelay: time.Millisecond, RetryMaxDelay: time.Millisecond,
	}, zerolog.Nop())
	c.StartRetryLoop(ctx)

	store := newFakeStore()
	rec := stubRecord()
	store.pending = []MitigationRecord{rec}

	w := NewWatcher(c, store, WatcherConfig{NodeName: "n"}, zerolog.Nop())
	go w.drainConfirmations(ctx)

	if err := w.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Wait for the retry loop to exhaust + confirmation drainer to
	// apply the result. Poll briefly to avoid flakiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if store.getState(rec.ID) == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if store.wasSent(rec.ID) {
		t.Fatal("row was MarkSent after retry exhaustion — BLOCKER 2 regression")
	}
	if got := store.getState(rec.ID); got != "failed" {
		t.Fatalf("state = %q, want failed", got)
	}
}

// TestSubmitDroppedSurfacesNotSilent asserts the buffer-overflow path
// does NOT silently lose evidence. SubmitDropped must come back from
// Submit so the caller can record the loss.
func TestSubmitDroppedSurfacesNotSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(Config{
		BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: 100 * time.Millisecond,
		RetryBufferSize: 1,
	}, zerolog.Nop())
	// Do NOT start the retry loop; queue stays full.

	// Fill the queue.
	out, err := c.Submit(context.Background(), map[string]any{"id": "first"})
	if err != nil || out != SubmitQueued {
		t.Fatalf("first submit: out=%v err=%v", out, err)
	}

	// Second submission must NOT silently succeed: the buffer is full,
	// so Submit reports SubmitDropped (and an error) so the watcher
	// can record the loss as state='failed' rather than 'sent'.
	confirmCh := c.Confirmations()
	out2, err2 := c.Submit(context.Background(), map[string]any{"id": "second"})
	if out2 != SubmitDropped {
		t.Fatalf("second submit outcome = %v, want SubmitDropped (buffer overflow)", out2)
	}
	if err2 == nil {
		t.Fatal("SubmitDropped must come with a non-nil error so the caller can log/metric it")
	}

	// Eviction should have produced exactly one confirmation marking
	// the evicted event as not delivered (no silent loss).
	select {
	case d := <-confirmCh:
		if d.Delivered {
			t.Fatal("evicted event reported as delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("no confirmation produced for evicted event — silent loss")
	}
}
