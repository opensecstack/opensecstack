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

	"github.com/rs/zerolog"
)

type stubMetrics struct {
	mu     sync.Mutex
	pushes map[string]int
}

func newStubMetrics() *stubMetrics { return &stubMetrics{pushes: map[string]int{}} }

func (s *stubMetrics) IncThreatFeedPush(target, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushes[target+":"+result]++
}

func sampleEvent() IOCEvent {
	return IOCEvent{
		Type:     "atlas_mapping",
		Severity: "high",
		Data:     json.RawMessage(`{"technique":"AML.T0051"}`),
	}
}

func TestPublish_FanOut(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	subs := []Subscriber{
		{ID: "s1", URL: srv.URL, HMACSecret: "k1", Active: true},
		{ID: "s2", URL: srv.URL, HMACSecret: "k2", Active: true},
		{ID: "s3", URL: srv.URL, HMACSecret: "k3", Active: true},
	}
	p := New(zerolog.Nop(), newStubMetrics(), subs)

	results := p.Publish(context.Background(), sampleEvent())
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("subscriber %s: %v", r.SubscriberID, r.Err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("server saw %d, want 3", got)
	}
}

func TestPublish_HMACSignature(t *testing.T) {
	const secret = "shhh"
	var (
		gotSig  string
		gotTS   string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-ThreatFlow-Signature")
		gotTS = r.Header.Get("X-ThreatFlow-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := New(zerolog.Nop(), newStubMetrics(), []Subscriber{
		{ID: "s1", URL: srv.URL, HMACSecret: secret, Active: true},
	})
	results := p.Publish(context.Background(), sampleEvent())
	if results[0].Err != nil {
		t.Fatalf("err: %v", results[0].Err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(gotTS))
	mac.Write([]byte("."))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("sig mismatch:\n got %s\nwant %s", gotSig, want)
	}
}

func TestPublish_FilterRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("subscriber with mismatched filter should not be called")
	}))
	defer srv.Close()

	p := New(zerolog.Nop(), newStubMetrics(), []Subscriber{
		{ID: "s1", URL: srv.URL, HMACSecret: "k", Active: true, Filters: []string{"ioc"}},
	})
	results := p.Publish(context.Background(), sampleEvent()) // type=atlas_mapping
	if len(results) != 0 {
		t.Fatalf("expected 0 deliveries, got %d", len(results))
	}
}

func TestPublish_RetryOn503(t *testing.T) {
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

	p := New(zerolog.Nop(), newStubMetrics(), []Subscriber{
		{ID: "s1", URL: srv.URL, HMACSecret: "k", Active: true},
	})
	results := p.Publish(context.Background(), sampleEvent())
	if results[0].Err != nil {
		t.Fatalf("err: %v", results[0].Err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestPublish_SkipsInactive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("inactive subscriber should not be called")
	}))
	defer srv.Close()

	p := New(zerolog.Nop(), newStubMetrics(), []Subscriber{
		{ID: "s1", URL: srv.URL, HMACSecret: "k", Active: false},
	})
	results := p.Publish(context.Background(), sampleEvent())
	if len(results) != 0 {
		t.Fatalf("expected 0 deliveries")
	}
}

func TestList_StripsSecrets(t *testing.T) {
	p := New(zerolog.Nop(), newStubMetrics(), []Subscriber{
		{ID: "s1", URL: "http://x", HMACSecret: "secret", Active: true},
	})
	for _, s := range p.List() {
		if s.HMACSecret != "" {
			t.Fatalf("List() leaked HMACSecret")
		}
	}
}
