package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type stubMetrics struct {
	mu     sync.Mutex
	counts map[string]int
}

func (s *stubMetrics) IncRateLimited(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	s.counts[scope]++
}

func TestAllow_BurstThenLimit(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 3})
	defer l.Stop()

	for i := 0; i < 3; i++ {
		if !l.Allow("k1") {
			t.Fatalf("allow %d should succeed (within burst)", i)
		}
	}
	if l.Allow("k1") {
		t.Fatal("4th request should be rate-limited")
	}
}

func TestAllow_PerKey(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1})
	defer l.Stop()
	if !l.Allow("a") {
		t.Fatal("a should pass")
	}
	if !l.Allow("b") {
		t.Fatal("b should pass independently of a")
	}
}

func TestMiddleware_429(t *testing.T) {
	l := New(Config{RPS: 1, Burst: 1})
	defer l.Stop()
	m := &stubMetrics{}
	logger := zerolog.Nop()
	mw := Middleware(l, m, &logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	r1, _ := http.Get(srv.URL)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first = %d, want 200", r1.StatusCode)
	}
	r2, _ := http.Get(srv.URL)
	r2.Body.Close()
	if r2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second = %d, want 429", r2.StatusCode)
	}
	if m.counts["ip"] != 1 {
		t.Fatalf("ip rate-limit metric = %d, want 1", m.counts["ip"])
	}
}

func TestJanitor_EvictsIdle(t *testing.T) {
	l := New(Config{RPS: 100, Burst: 1, CleanupInterval: 50 * time.Millisecond, IdleTTL: 100 * time.Millisecond})
	defer l.Stop()
	l.Allow("transient")
	time.Sleep(250 * time.Millisecond)
	l.mu.Lock()
	_, present := l.buckets["transient"]
	l.mu.Unlock()
	if present {
		t.Fatal("idle bucket should have been evicted")
	}
}
