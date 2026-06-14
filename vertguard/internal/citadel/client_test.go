package citadel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type fakeMetrics struct {
	mu       sync.Mutex
	worm     map[string]int
	calls    map[string]int
	queueLen int
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{worm: map[string]int{}, calls: map[string]int{}}
}

func (f *fakeMetrics) IncWORMEmit(eventType, result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.worm[eventType+":"+result]++
}
func (f *fakeMetrics) IncCitadelCall(target, result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[target+":"+result]++
}
func (f *fakeMetrics) ObserveCitadelLatency(string, float64) {}
func (f *fakeMetrics) SetCitadelQueueDepth(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queueLen = n
}

func discardLogger() zerolog.Logger { return zerolog.Nop() }

func sampleEvidence() Evidence {
	return Evidence{
		EventType:     "prompt_scan",
		Subject:       "abc123",
		Verdict:       "block",
		Score:         0.91,
		Categories:    []string{"LLM01"},
		Patterns:      []string{"LLM01.instruction_override.v1"},
		Tenant:        "asni",
		Timestamp:     time.Unix(1700000000, 0).UTC(),
		CorrelationID: "corr-1",
	}
}

func TestEmitWORM_Success(t *testing.T) {
	const secret = "s3cr3t"

	var got struct {
		body []byte
		sig  string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/worm/emit" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		got.body, _ = io.ReadAll(r.Body)
		got.sig = r.Header.Get("X-VertGuard-Signature")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: secret}, discardLogger(), newFakeMetrics())
	defer c.Close()

	if err := c.EmitWORM(context.Background(), sampleEvidence()); err != nil {
		t.Fatalf("EmitWORM: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(got.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got.sig != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", got.sig, want)
	}
}

func TestEmitWORM_RetriesOn5xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "x"}, discardLogger(), newFakeMetrics())
	defer c.Close()

	if err := c.EmitWORM(context.Background(), sampleEvidence()); err != nil {
		t.Fatalf("EmitWORM: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestEmitWORM_NoRetryOn4xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "x"}, discardLogger(), newFakeMetrics())
	defer c.Close()

	if err := c.EmitWORM(context.Background(), sampleEvidence()); err == nil {
		t.Fatal("expected error on 400")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("attempts = %d, want 1 (no retry on 4xx)", got)
	}
}

func TestEmitAsync_DrainsOnClose(t *testing.T) {
	var seen int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&seen, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "x", AsyncBuffer: 16}, discardLogger(), newFakeMetrics())

	for i := 0; i < 5; i++ {
		if !c.EmitAsync(context.Background(), sampleEvidence()) {
			t.Fatalf("EmitAsync rejected event %d", i)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := atomic.LoadInt32(&seen); got != 5 {
		t.Fatalf("server saw %d events, want 5", got)
	}
}

func TestEmitAsync_RejectsAfterClose(t *testing.T) {
	c := New(Config{DryRun: true}, discardLogger(), newFakeMetrics())
	_ = c.Close()
	if c.EmitAsync(context.Background(), sampleEvidence()) {
		t.Fatal("EmitAsync should return false after Close")
	}
}

func TestEmitWORM_DryRun(t *testing.T) {
	m := newFakeMetrics()
	c := New(Config{DryRun: true}, discardLogger(), m)
	defer c.Close()

	if err := c.EmitWORM(context.Background(), sampleEvidence()); err != nil {
		t.Fatalf("dry run should succeed: %v", err)
	}
	if m.worm["prompt_scan:dry_run"] != 1 {
		t.Fatalf("dry_run metric not incremented: %+v", m.worm)
	}
}
