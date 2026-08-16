// Package citadel — outbox worker tests.
//
// Stdlib-only (matches vertguard's no-testify convention). The mocks
// below are simple in-memory fakes; the worker itself is exercised
// by driving a single poll cycle and asserting on the recorded
// store + dispatch calls.
package citadel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// ── fakes ─────────────────────────────────────────────────────────

type fakeOutbox struct {
	mu sync.Mutex

	// queue of batches Claim returns; once exhausted Claim returns
	// nil, nil to simulate an empty queue.
	batches    [][]OutboxEntry
	claimCalls int

	delivered []int64
	failed    []failedCall
	dlqIDs    []int64

	// dlqAfter — number of times a given id has been MarkFailed'd
	// before MarkFailed is told to flip it to dlq. Mirrors the
	// store's >10-attempts cap.
	attemptsByID map[int64]int
	dlqAfter     int
}

type failedCall struct {
	ID        int64
	Err       string
	Retryable bool
}

func newFakeOutbox(dlqAfter int) *fakeOutbox {
	return &fakeOutbox{
		attemptsByID: map[int64]int{},
		dlqAfter:     dlqAfter,
	}
}

func (f *fakeOutbox) push(batch []OutboxEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, batch)
}

func (f *fakeOutbox) Claim(ctx context.Context, batchSize int) ([]OutboxEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimCalls++
	if len(f.batches) == 0 {
		return nil, nil
	}
	out := f.batches[0]
	f.batches = f.batches[1:]
	return out, nil
}

func (f *fakeOutbox) MarkDelivered(ctx context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = append(f.delivered, id)
	return nil
}

func (f *fakeOutbox) MarkFailed(ctx context.Context, id int64, errMsg string, retryable bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, failedCall{ID: id, Err: errMsg, Retryable: retryable})
	if !retryable {
		f.dlqIDs = append(f.dlqIDs, id)
		return true, nil
	}
	f.attemptsByID[id]++
	if f.attemptsByID[id] >= f.dlqAfter {
		f.dlqIDs = append(f.dlqIDs, id)
		return true, nil
	}
	return false, nil
}

type fakeMetrics struct {
	mu              sync.Mutex
	enqueued        int
	delivered       int
	failedRetryable int
	failedHard      int
	dlq             int
	inFlightDelta   atomic.Int64
}

func (m *fakeMetrics) IncEnqueued(string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueued++
}
func (m *fakeMetrics) IncDelivered(string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delivered++
}
func (m *fakeMetrics) IncFailed(_ string, _ string, retryable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if retryable {
		m.failedRetryable++
	} else {
		m.failedHard++
	}
}
func (m *fakeMetrics) IncDLQ() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dlq++
}
func (m *fakeMetrics) IncInFlight()                                    { m.inFlightDelta.Add(1) }
func (m *fakeMetrics) DecInFlight()                                    { m.inFlightDelta.Add(-1) }
func (m *fakeMetrics) ObserveDeliveryDuration(string, string, float64) {}

// ── helpers ───────────────────────────────────────────────────────

// runOneCycle starts the worker, waits long enough for it to drain
// the seeded batches, then cancels the context and waits for exit.
func runOneCycle(t *testing.T, w *Worker) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Generous bound: 200ms is well above one poll cycle for tests
	// (PollInterval is set short below).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Cheap synchronisation: wait until the worker has at least
		// finished one Claim and either marked delivered or failed.
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	w.Wait()
}

func newTestLogger() zerolog.Logger {
	return zerolog.Nop()
}

// ── tests ─────────────────────────────────────────────────────────

// Happy path: one entry → CITADEL succeeds (dry-run client) →
// MarkDelivered called.
func TestWorker_Delivers(t *testing.T) {
	store := newFakeOutbox(11)
	store.push([]OutboxEntry{
		{
			ID:            42,
			Destination:   "citadel",
			EventType:     "cyberpath.completion",
			Payload:       []byte(`{"subject":"user:abc"}`),
			CorrelationID: "cor-1",
		},
	})
	metrics := &fakeMetrics{}
	citadelClient := New(Config{DryRun: true}, newTestLogger())

	w := NewWorker(Options{
		Outbox:       store,
		Citadel:      citadelClient,
		Metrics:      metrics,
		Logger:       newTestLogger(),
		Workers:      1,
		BatchSize:    10,
		PollInterval: 30 * time.Millisecond,
	})
	runOneCycle(t, w)

	if len(store.delivered) != 1 || store.delivered[0] != 42 {
		t.Fatalf("expected delivered=[42], got %v", store.delivered)
	}
	if len(store.failed) != 0 {
		t.Fatalf("expected no failures, got %+v", store.failed)
	}
	if metrics.delivered != 1 {
		t.Fatalf("expected metrics.delivered=1, got %d", metrics.delivered)
	}
	if !w.IsHealthy() {
		t.Fatalf("expected worker to report healthy after delivery")
	}
}

// 5xx from a webhook target → MarkFailed retryable=true, NOT
// flipped to dlq on first attempt.
func TestWorker_RetryableFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	store := newFakeOutbox(11)
	store.push([]OutboxEntry{
		{
			ID:          7,
			Destination: "webhook",
			WebhookID:   "hook-1",
			EventType:   "cyberpath.cohort.created",
			Payload:     []byte(`{"x":1}`),
		},
	})
	hooks := &fakeWebhookStore{
		records: map[string]*WebhookRecord{
			"hook-1": {ID: "hook-1", URL: srv.URL, SecretHMAC: "s", Active: true},
		},
	}
	metrics := &fakeMetrics{}

	w := NewWorker(Options{
		Outbox:       store,
		Webhooks:     hooks,
		Metrics:      metrics,
		Logger:       newTestLogger(),
		Workers:      1,
		BatchSize:    10,
		PollInterval: 30 * time.Millisecond,
		HTTPTimeout:  500 * time.Millisecond,
	})
	runOneCycle(t, w)

	if len(store.delivered) != 0 {
		t.Fatalf("expected no deliveries, got %v", store.delivered)
	}
	if len(store.failed) == 0 {
		t.Fatalf("expected MarkFailed, got none")
	}
	if !store.failed[0].Retryable {
		t.Fatalf("expected retryable=true for 5xx, got false")
	}
	if metrics.failedRetryable == 0 {
		t.Fatalf("expected metrics.failedRetryable >= 1, got 0")
	}
	if metrics.dlq != 0 {
		t.Fatalf("expected no dlq on first 5xx, got %d", metrics.dlq)
	}
}

// Repeated retryable failures eventually trip the DLQ once attempts
// exceed the cap. The fakeOutbox's dlqAfter==11 mirrors the prod
// rule "after attempts > 10 → dlq".
func TestWorker_DLQAfterCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	store := newFakeOutbox(11)
	// 11 separate batches, each with the same id, so 11 attempts.
	for i := 0; i < 11; i++ {
		store.push([]OutboxEntry{{
			ID:          99,
			Destination: "webhook",
			WebhookID:   "hook-1",
			EventType:   "cyberpath.lab.completed",
			Payload:     []byte(`{}`),
		}})
	}
	hooks := &fakeWebhookStore{
		records: map[string]*WebhookRecord{
			"hook-1": {ID: "hook-1", URL: srv.URL, SecretHMAC: "s", Active: true},
		},
	}
	metrics := &fakeMetrics{}

	w := NewWorker(Options{
		Outbox:       store,
		Webhooks:     hooks,
		Metrics:      metrics,
		Logger:       newTestLogger(),
		Workers:      1,
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		HTTPTimeout:  500 * time.Millisecond,
	})
	runOneCycle(t, w)

	if len(store.failed) < 11 {
		t.Fatalf("expected >=11 MarkFailed calls, got %d", len(store.failed))
	}
	if len(store.dlqIDs) == 0 {
		t.Fatalf("expected at least one row moved to DLQ, got none")
	}
	if metrics.dlq == 0 {
		t.Fatalf("expected metrics.dlq >= 1, got 0")
	}
}

// errIsRetryable contract: nil → false, non-retryable wrapper →
// false, anything else → true.
func TestErrIsRetryable(t *testing.T) {
	if errIsRetryable(nil) {
		t.Fatalf("nil should not be retryable")
	}
	if errIsRetryable(&nonRetryableError{err: errors.New("schema")}) {
		t.Fatalf("nonRetryableError should not be retryable")
	}
	if !errIsRetryable(&retryableError{err: errors.New("5xx")}) {
		t.Fatalf("retryableError should be retryable")
	}
	if !errIsRetryable(errors.New("random")) {
		t.Fatalf("unknown errors should default to retryable")
	}
}

// Webhook 4xx (non-408/429) is non-retryable → flip straight to DLQ.
func TestWorker_Webhook4xxToDLQImmediately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	store := newFakeOutbox(11)
	store.push([]OutboxEntry{{
		ID:          5,
		Destination: "webhook",
		WebhookID:   "hook-1",
		EventType:   "cyberpath.cohort.created",
		Payload:     []byte(`{}`),
	}})
	hooks := &fakeWebhookStore{
		records: map[string]*WebhookRecord{
			"hook-1": {ID: "hook-1", URL: srv.URL, SecretHMAC: "s", Active: true},
		},
	}
	metrics := &fakeMetrics{}

	w := NewWorker(Options{
		Outbox:       store,
		Webhooks:     hooks,
		Metrics:      metrics,
		Logger:       newTestLogger(),
		Workers:      1,
		BatchSize:    10,
		PollInterval: 30 * time.Millisecond,
		HTTPTimeout:  500 * time.Millisecond,
	})
	runOneCycle(t, w)

	if len(store.failed) == 0 || store.failed[0].Retryable {
		t.Fatalf("expected non-retryable failure for 4xx, got %+v", store.failed)
	}
	if len(store.dlqIDs) == 0 || metrics.dlq == 0 {
		t.Fatalf("expected immediate DLQ on 4xx, got dlqIDs=%v dlqMetric=%d", store.dlqIDs, metrics.dlq)
	}
}

// fakeWebhookStore satisfies WebhookStore.
type fakeWebhookStore struct {
	records map[string]*WebhookRecord
}

func (f *fakeWebhookStore) GetWebhook(_ context.Context, id string) (*WebhookRecord, error) {
	r, ok := f.records[id]
	if !ok {
		return nil, nil
	}
	return r, nil
}
