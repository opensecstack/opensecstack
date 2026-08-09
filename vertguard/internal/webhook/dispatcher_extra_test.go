package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func TestDispatch_NoPrimarySecretConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("must not send an unsigned request")
	}))
	defer srv.Close()

	sub := Subscriber{ID: uuid.New(), URL: srv.URL, Enabled: true} // no HMACSecrets at all
	store := newFakeStore(sub)
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 2, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, store, store, zerolog.Nop(), metrics)

	disp.Publish(context.Background(), Event{ID: "evt-nosecret", Type: "prompt_scan"})

	if metrics.get("fail") != 1 {
		t.Fatalf("metrics fail=%d, want 1 (missing primary secret is a permanent failure)", metrics.get("fail"))
	}
	if store.deliveredCount() != 0 {
		t.Fatal("must not mark delivered when no primary secret is configured")
	}
}

func TestDispatcher_RecordRotation(t *testing.T) {
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true}, nil, nil, zerolog.Nop(), metrics)

	disp.RecordRotation()

	if metrics.get("rotate") != 1 {
		t.Fatalf("metrics rotate=%d, want 1", metrics.get("rotate"))
	}
}

func TestDispatcher_RecordRotation_NilSafe(t *testing.T) {
	var disp *Dispatcher
	disp.RecordRotation() // must not panic
}

func TestDispatcher_Publish_NilSafe(t *testing.T) {
	var disp *Dispatcher
	disp.Publish(context.Background(), Event{Type: "x"}) // must not panic
}

func TestDispatcher_StartStop_FlushesOutbox(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{
		Enabled:             true,
		MaxRetries:          1,
		BackoffBase:         time.Millisecond,
		OutboxFlushInterval: 10 * time.Millisecond,
		RequestTimeout:      time.Second,
	}, store, store, zerolog.Nop(), metrics)

	// Enqueue a row directly (bypassing Publish) to simulate a row left
	// over from a crash before the in-process delivery happened.
	row := &OutboxRow{SubscriberID: sub.ID, EventID: "evt-flush", EventType: "prompt_scan", Payload: []byte(`{}`)}
	if err := store.EnqueueOutbox(context.Background(), row); err != nil {
		t.Fatalf("EnqueueOutbox() error = %v", err)
	}

	disp.Start()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for background flush to deliver the outbox row")
		case <-ticker.C:
			if store.deliveredCount() == 1 {
				break loop
			}
		}
	}
	disp.Stop()

	if atomic.LoadInt32(&hits) == 0 {
		t.Error("expected at least one HTTP delivery attempt from the flush loop")
	}
}

func TestDispatcher_Stop_NilSafe(t *testing.T) {
	var disp *Dispatcher
	disp.Stop() // must not panic
}

func TestDispatcher_Stop_IdempotentWithoutStart(t *testing.T) {
	disp := NewDispatcher(Config{Enabled: true}, nil, nil, zerolog.Nop(), nil)
	disp.Stop()
	disp.Stop() // second call must not panic on an already-closed channel
}

// listErrStore returns an error from ListByEventType to exercise
// Publish's early-return-on-list-failure branch.
type listErrStore struct{ *fakeStore }

func (l listErrStore) ListByEventType(context.Context, string) ([]Subscriber, error) {
	return nil, errBoom
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom" }

func TestDispatch_ListSubscribersError(t *testing.T) {
	base := newFakeStore()
	store := listErrStore{base}
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, store, base, zerolog.Nop(), newStubMetrics())

	// Must return cleanly without panicking despite the list error.
	disp.Publish(context.Background(), Event{ID: "evt-listerr", Type: "prompt_scan"})

	if base.deliveredCount() != 0 {
		t.Error("nothing should be delivered when subscriber listing fails")
	}
}
