package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

func TestNewDispatcher_SetsDefaults(t *testing.T) {
	d := NewDispatcher(nil, zerolog.Nop())
	if d.maxAttempts != 4 {
		t.Errorf("maxAttempts = %d, want 4", d.maxAttempts)
	}
	if d.baseBackoff != 500*time.Millisecond {
		t.Errorf("baseBackoff = %v, want 500ms", d.baseBackoff)
	}
	if d.http == nil {
		t.Fatal("http client must be set")
	}
	if d.http.Timeout != 15*time.Second {
		t.Errorf("http timeout = %v, want 15s", d.http.Timeout)
	}
	if cap(d.sem) != 64 {
		t.Errorf("sem capacity = %d, want 64", cap(d.sem))
	}
}

// TestEmit_NilDispatcherIsNoOp proves Emit is safe to call on a nil
// *Dispatcher — handlers hold this pointer optionally and call Emit
// unconditionally.
func TestEmit_NilDispatcherIsNoOp(t *testing.T) {
	var d *Dispatcher
	// Must not panic.
	d.Emit(context.Background(), EventIOCCreated, "threatflow", 50, map[string]string{"a": "b"})
}

// TestEmit_NilWebhookStoreIsNoOp proves Emit returns immediately (without
// touching the store) when persistence is disabled, matching the documented
// "any optional dependency may be nil" contract used across handlers.
func TestEmit_NilWebhookStoreIsNoOp(t *testing.T) {
	d := NewDispatcher(nil, zerolog.Nop())
	// If this reached d.webhooks.MatchingSubscribers it would nil-pointer
	// panic (webhooks field is nil), so a clean return proves the guard.
	d.Emit(context.Background(), EventIOCCreated, "threatflow", 50, map[string]string{"a": "b"})
}

func TestDrain_NilDispatcherIsNoOp(t *testing.T) {
	var d *Dispatcher
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	d.Drain(ctx) // must return promptly, not block until ctx deadline
}

func TestDrain_ReturnsImmediatelyWithNoInFlightDeliveries(t *testing.T) {
	d := NewDispatcher(nil, zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	d.Drain(ctx)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Drain took %v with no in-flight work, want near-instant", elapsed)
	}
}

func TestDeliverOnce_SendsSignedRequestAndReturnsStatus(t *testing.T) {
	var gotSig, gotTS, gotEventID string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-ThreatFlow-Signature")
		gotTS = r.Header.Get("X-ThreatFlow-Timestamp")
		gotEventID = r.Header.Get("X-ThreatFlow-Event-ID")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher(nil, zerolog.Nop())
	sub := &store.WebhookSubscriber{URL: server.URL, Secret: "topsecret"}
	eventID := uuid.New()
	envelope := []byte(`{"hello":"world"}`)

	code, err := d.deliverOnce(context.Background(), sub, eventID, envelope)
	if err != nil {
		t.Fatalf("deliverOnce: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if gotEventID != eventID.String() {
		t.Errorf("event ID header = %q, want %q", gotEventID, eventID.String())
	}
	if !VerifySignature("topsecret", gotTS, gotSig, envelope) {
		t.Errorf("server-observed signature %q did not verify against envelope", gotSig)
	}
	if string(gotBody) != string(envelope) {
		t.Errorf("body = %q, want %q", gotBody, envelope)
	}
}

func TestDeliverOnce_ReturnsServerErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	d := NewDispatcher(nil, zerolog.Nop())
	sub := &store.WebhookSubscriber{URL: server.URL, Secret: "s"}

	code, err := d.deliverOnce(context.Background(), sub, uuid.New(), []byte(`{}`))
	if err != nil {
		t.Fatalf("deliverOnce: %v", err)
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", code)
	}
}

func TestDeliverOnce_NetworkErrorReturnsErrorNotPanic(t *testing.T) {
	d := NewDispatcher(nil, zerolog.Nop())
	sub := &store.WebhookSubscriber{URL: "http://127.0.0.1:1/unreachable", Secret: "s"}

	code, err := d.deliverOnce(context.Background(), sub, uuid.New(), []byte(`{}`))
	if err == nil {
		t.Fatal("expected network error for unreachable subscriber URL")
	}
	if code != 0 {
		t.Errorf("code = %d, want 0 on network error", code)
	}
}

// TestEmit_MarshalErrorReturnsBeforeTouchingStore proves Emit bails out on
// an unmarshalable payload before ever calling MatchingSubscribers. This is
// the only Emit branch reachable without a live *store.WebhookStore
// (MatchingSubscribers/RecordDelivery are concrete pgxpool-backed methods
// with no fake/interface seam) — passing a non-nil *store.WebhookStore here
// proves the marshal error short-circuits before the store is ever touched
// (a nil pool would panic if Query/QueryRow were reached).
func TestEmit_MarshalErrorReturnsBeforeTouchingStore(t *testing.T) {
	d := NewDispatcher(store.NewWebhookStore(nil), zerolog.Nop())
	// channels cannot be JSON-marshaled.
	unmarshalable := make(chan int)
	// Must not panic despite d.webhooks having a nil pool.
	d.Emit(context.Background(), EventIOCCreated, "threatflow", 50, unmarshalable)
}

func TestDeliverOnce_InvalidURLReturnsError(t *testing.T) {
	d := NewDispatcher(nil, zerolog.Nop())
	sub := &store.WebhookSubscriber{URL: "://not-a-valid-url", Secret: "s"}

	_, err := d.deliverOnce(context.Background(), sub, uuid.New(), []byte(`{}`))
	if err == nil {
		t.Fatal("expected error constructing request for invalid URL")
	}
}
