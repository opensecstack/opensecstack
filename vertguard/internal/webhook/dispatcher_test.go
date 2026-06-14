package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// fakeStore implements SubscriberLister + OutboxRepo in memory so the
// dispatcher can be exercised without postgres.
type fakeStore struct {
	mu         sync.Mutex
	subs       []Subscriber
	outbox     map[uuid.UUID]*OutboxRow
	delivered  map[uuid.UUID]bool
	attemptLog map[uuid.UUID]int
}

func newFakeStore(subs ...Subscriber) *fakeStore {
	return &fakeStore{
		subs:       subs,
		outbox:     map[uuid.UUID]*OutboxRow{},
		delivered:  map[uuid.UUID]bool{},
		attemptLog: map[uuid.UUID]int{},
	}
}

func (f *fakeStore) ListByEventType(_ context.Context, eventType string) ([]Subscriber, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Subscriber, 0, len(f.subs))
	for i := range f.subs {
		if f.subs[i].Enabled && f.subs[i].Matches(eventType) {
			out = append(out, f.subs[i])
		}
	}
	return out, nil
}

func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (*Subscriber, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.subs {
		if f.subs[i].ID == id {
			s := f.subs[i]
			return &s, nil
		}
	}
	return nil, ErrNotFound
}

func (f *fakeStore) EnqueueOutbox(_ context.Context, row *OutboxRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if row.ID == uuid.Nil {
		row.ID = uuid.New()
	}
	cp := *row
	f.outbox[row.ID] = &cp
	return nil
}

func (f *fakeStore) FetchPendingOutbox(_ context.Context, limit int) ([]OutboxRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []OutboxRow{}
	for _, r := range f.outbox {
		if !f.delivered[r.ID] {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakeStore) MarkDelivered(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered[id] = true
	return nil
}

func (f *fakeStore) MarkAttempt(_ context.Context, id uuid.UUID, _ string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attemptLog[id]++
	return nil
}

func (f *fakeStore) OutboxSize(_ context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for id := range f.outbox {
		if !f.delivered[id] {
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) deliveredCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, ok := range f.delivered {
		if ok {
			n++
		}
	}
	return n
}

func (f *fakeStore) attempts(id uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attemptLog[id]
}

type stubMetrics struct {
	mu      sync.Mutex
	results map[string]int
}

func newStubMetrics() *stubMetrics                      { return &stubMetrics{results: map[string]int{}} }
func (s *stubMetrics) IncWebhookDispatch(r string)      { s.mu.Lock(); s.results[r]++; s.mu.Unlock() }
func (s *stubMetrics) ObserveWebhookLatency(_ float64)  {}
func (s *stubMetrics) SetWebhookOutboxSize(_ int)       {}
func (s *stubMetrics) IncWebhookRotation()              { s.mu.Lock(); s.results["rotate"]++; s.mu.Unlock() }
func (s *stubMetrics) get(r string) int                 { s.mu.Lock(); defer s.mu.Unlock(); return s.results[r] }

func newSub(url, primarySecret, kid string) Subscriber {
	return Subscriber{
		ID:          uuid.New(),
		URL:         url,
		EventTypes:  nil,
		HMACSecrets: []string{primarySecret, "", ""},
		KeyIDs:      []string{kid, "", ""},
		Enabled:     true,
	}
}

func TestDispatch_SignaturePrimarySlot(t *testing.T) {
	const secret = "primary-secret"
	const kid = "kid-001"

	var (
		gotSig string
		gotKid string
		gotTs  string
		gotEv  string
		body   []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-VertGuard-Signature")
		gotKid = r.Header.Get("X-VertGuard-Key-Id")
		gotTs = r.Header.Get("X-VertGuard-Timestamp")
		gotEv = r.Header.Get("X-VertGuard-Event-Id")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, secret, kid)
	store := newFakeStore(sub)
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 3, BackoffBase: 1 * time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), newStubMetrics())

	disp.Publish(context.Background(), Event{ID: "evt-1", Type: "prompt_scan", Data: json.RawMessage(`{"k":"v"}`)})

	if gotKid != kid {
		t.Fatalf("X-VertGuard-Key-Id = %q, want %q", gotKid, kid)
	}
	if gotEv != "evt-1" {
		t.Fatalf("X-VertGuard-Event-Id = %q, want %q", gotEv, "evt-1")
	}
	want := "sha256=" + hexSign(secret, gotTs, body)
	if gotSig != want {
		t.Fatalf("signature mismatch: got %q want %q", gotSig, want)
	}
	if store.deliveredCount() != 1 {
		t.Fatalf("delivered=%d, want 1", store.deliveredCount())
	}
}

func hexSign(secret, ts string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func TestDispatch_RetriesOn5xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 3, BackoffBase: 1 * time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), metrics)

	disp.Publish(context.Background(), Event{ID: "evt-2", Type: "prompt_scan"})

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits=%d, want 3 (retried until success)", got)
	}
	if store.deliveredCount() != 1 {
		t.Fatalf("delivered=%d, want 1", store.deliveredCount())
	}
	if metrics.get("ok") != 1 {
		t.Fatalf("metrics ok=%d, want 1", metrics.get("ok"))
	}
}

func TestDispatch_GivesUpAfterMaxRetries_OutboxPersisted(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	metrics := newStubMetrics()
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 3, BackoffBase: 1 * time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), metrics)

	disp.Publish(context.Background(), Event{ID: "evt-3", Type: "prompt_scan"})

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits=%d, want 3 (max retries)", got)
	}
	if store.deliveredCount() != 0 {
		t.Fatalf("delivered=%d, want 0 (all attempts failed)", store.deliveredCount())
	}
	// Outbox row remains pending — operator-visible.
	size, _ := store.OutboxSize(context.Background())
	if size != 1 {
		t.Fatalf("outbox size=%d, want 1 (row persisted on permanent failure)", size)
	}
	if metrics.get("fail") != 1 {
		t.Fatalf("metrics fail=%d, want 1", metrics.get("fail"))
	}
}

func TestDispatch_4xxNoRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 3, BackoffBase: 1 * time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), newStubMetrics())

	disp.Publish(context.Background(), Event{ID: "evt-4", Type: "prompt_scan"})

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits=%d, want 1 (4xx terminal)", got)
	}
}

func TestDispatch_DisabledIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("dispatcher must not POST when disabled")
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "s", "k")
	store := newFakeStore(sub)
	disp := NewDispatcher(Config{Enabled: false}, store, store, zerolog.Nop(), nil)
	disp.Publish(context.Background(), Event{Type: "any"})
}
