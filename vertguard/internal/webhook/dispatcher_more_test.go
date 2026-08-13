package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// TestDispatch_AutoAssignsIDAndTimestamp exercises Publish's defaulting
// branches: an Event with a zero ID and zero Timestamp must still be
// delivered, with both fields populated before signing/marshalling.
func TestDispatch_AutoAssignsIDAndTimestamp(t *testing.T) {
	var gotEventIDHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEventIDHeader = r.Header.Get("X-VertGuard-Event-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, store, store, zerolog.Nop(), newStubMetrics())

	// No ID, no Timestamp — both must be auto-assigned by Publish.
	disp.Publish(context.Background(), Event{Type: "prompt_scan", Data: json.RawMessage(`{}`)})

	if gotEventIDHeader == "" {
		t.Fatal("event ID header empty — ev.ID was not auto-assigned")
	}
	if store.deliveredCount() != 1 {
		t.Fatalf("delivered=%d, want 1", store.deliveredCount())
	}
}

// enqueueErrStore fails every EnqueueOutbox call so Publish's
// enqueue-error branch (log + continue to next subscriber) is exercised.
type enqueueErrStore struct{ *fakeStore }

func (e enqueueErrStore) EnqueueOutbox(context.Context, *OutboxRow) error { return errBoom }

func TestDispatch_EnqueueOutboxErrorSkipsSubscriberButDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("must not attempt delivery when enqueue fails")
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	base := newFakeStore(sub)
	store := enqueueErrStore{base}
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, base, store, zerolog.Nop(), newStubMetrics())

	disp.Publish(context.Background(), Event{ID: "evt-enqueue-err", Type: "prompt_scan"})

	if base.deliveredCount() != 0 {
		t.Error("nothing should be delivered when enqueue fails")
	}
}

func TestDispatch_ContextCancelledDuringBackoffAbortsRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway) // always retryable
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	// Backoff long enough that the context deadline fires while the
	// dispatcher is sleeping between attempt 1 and attempt 2.
	disp := NewDispatcher(Config{
		Enabled: true, MaxRetries: 5, BackoffBase: 500 * time.Millisecond, RequestTimeout: time.Second,
	}, store, store, zerolog.Nop(), newStubMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	disp.Publish(ctx, Event{ID: "evt-ctxcancel", Type: "prompt_scan"})

	if store.deliveredCount() != 0 {
		t.Error("must not mark delivered when retry loop aborted via context")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits=%d, want exactly 1 (aborted before second attempt)", got)
	}
}

// markDeliveredErrStore fails MarkDelivered so deliverWithRetry's
// success-path error-logging branch is exercised.
type markDeliveredErrStore struct{ *fakeStore }

func (m markDeliveredErrStore) MarkDelivered(context.Context, uuid.UUID) error { return errBoom }

func TestDispatch_MarkDeliveredErrorIsLoggedNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	base := newFakeStore(sub)
	store := markDeliveredErrStore{base}
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, base, store, zerolog.Nop(), metrics)

	// Must not panic even though MarkDelivered fails.
	disp.Publish(context.Background(), Event{ID: "evt-markdeliverederr", Type: "prompt_scan"})

	if metrics.get("ok") != 1 {
		t.Fatalf("metrics ok=%d, want 1 (HTTP succeeded even though the store write failed)", metrics.get("ok"))
	}
}

// markAttemptErrStore fails MarkAttempt so deliverWithRetry's
// give-up-path error-logging branch is exercised.
type markAttemptErrStore struct{ *fakeStore }

func (m markAttemptErrStore) MarkAttempt(context.Context, uuid.UUID, string, time.Duration) error {
	return errBoom
}

func TestDispatch_MarkAttemptErrorIsLoggedNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // terminal, non-retryable
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	base := newFakeStore(sub)
	store := markAttemptErrStore{base}
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, base, store, zerolog.Nop(), metrics)

	// Must not panic even though MarkAttempt fails.
	disp.Publish(context.Background(), Event{ID: "evt-markattempterr", Type: "prompt_scan"})

	if metrics.get("fail") != 1 {
		t.Fatalf("metrics fail=%d, want 1", metrics.get("fail"))
	}
}

func TestDispatch_InvalidSubscriberURLIsPermanentFailure(t *testing.T) {
	sub := newSub("http://exa\nmple.com", "s", "k") // control char -> NewRequestWithContext error
	store := newFakeStore(sub)
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 2, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, store, store, zerolog.Nop(), metrics)

	disp.Publish(context.Background(), Event{ID: "evt-badurl", Type: "prompt_scan"})

	if metrics.get("fail") != 1 {
		t.Fatalf("metrics fail=%d, want 1 (malformed URL is a permanent failure, not retried)", metrics.get("fail"))
	}
}

func TestDispatch_UnreachableHostIsRetryableNetworkError(t *testing.T) {
	sub := newSub("http://127.0.0.1:1/webhook", "s", "k") // reserved port, nothing listens
	store := newFakeStore(sub)
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 2, BackoffBase: time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), metrics)

	disp.Publish(context.Background(), Event{ID: "evt-unreachable", Type: "prompt_scan"})

	if metrics.get("fail") != 1 {
		t.Fatalf("metrics fail=%d, want 1 (exhausted retries against unreachable host)", metrics.get("fail"))
	}
	if store.deliveredCount() != 0 {
		t.Error("must not mark delivered for an unreachable host")
	}
}

func TestDispatcher_Start_NilSafe(t *testing.T) {
	var disp *Dispatcher
	disp.Start() // must not panic
}

func TestDispatcher_Start_DisabledIsNoop(t *testing.T) {
	disp := NewDispatcher(Config{Enabled: false}, nil, nil, zerolog.Nop(), nil)
	disp.Start() // must return immediately without launching flushLoop
	disp.Stop()  // safe even though Start() never ran the goroutine
}

// fetchPendingErrStore fails FetchPendingOutbox so flushOnce's
// fetch-error branch (log + return) is exercised.
type fetchPendingErrStore struct{ *fakeStore }

func (f fetchPendingErrStore) FetchPendingOutbox(context.Context, int) ([]OutboxRow, error) {
	return nil, errBoom
}

func TestDispatcher_FlushOnce_FetchErrorReturnsCleanly(t *testing.T) {
	base := newFakeStore()
	store := fetchPendingErrStore{base}
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, store, store, zerolog.Nop(), newStubMetrics())

	disp.flushOnce(context.Background()) // must not panic
}

// getErrLister wraps fakeStore but returns an error from Get, used to
// exercise flushOnce's subscriber-lookup-failure branch.
type getErrLister struct{ *fakeStore }

func (g getErrLister) Get(context.Context, uuid.UUID) (*Subscriber, error) {
	return nil, errBoom
}

func TestDispatcher_FlushOnce_SubscriberLookupErrorSkipsRow(t *testing.T) {
	sub := newSub("http://example.invalid", "s", "k")
	base := newFakeStore(sub)
	row := &OutboxRow{SubscriberID: sub.ID, EventID: "evt-lookuperr", EventType: "prompt_scan", Payload: []byte(`{}`)}
	if err := base.EnqueueOutbox(context.Background(), row); err != nil {
		t.Fatalf("EnqueueOutbox() error = %v", err)
	}
	lister := getErrLister{base}
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, lister, base, zerolog.Nop(), newStubMetrics())

	disp.flushOnce(context.Background()) // must not panic, row stays pending

	if base.deliveredCount() != 0 {
		t.Error("row must remain pending when subscriber lookup fails")
	}
}

// noGetLister implements only SubscriberLister (no Get method), so
// flushOnce must hit the "does not support Get" branch and skip.
type noGetLister struct{}

func (noGetLister) ListByEventType(context.Context, string) ([]Subscriber, error) {
	return nil, nil
}

func TestDispatcher_FlushOnce_ListerWithoutGetSkipsRows(t *testing.T) {
	base := newFakeStore()
	sub := newSub("http://example.invalid", "s", "k")
	row := &OutboxRow{SubscriberID: sub.ID, EventID: "evt-noget", EventType: "prompt_scan", Payload: []byte(`{}`)}
	if err := base.EnqueueOutbox(context.Background(), row); err != nil {
		t.Fatalf("EnqueueOutbox() error = %v", err)
	}
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: time.Second}, noGetLister{}, base, zerolog.Nop(), newStubMetrics())

	disp.flushOnce(context.Background()) // must not panic

	if base.deliveredCount() != 0 {
		t.Error("row must remain pending when the lister doesn't support Get")
	}
}
