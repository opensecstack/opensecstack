package irflow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestClient(t *testing.T, baseURL, secret string) *Client {
	t.Helper()
	return New(Options{
		BaseURL:     baseURL,
		HMACSecret:  secret,
		HTTPTimeout: 1 * time.Second,
		MaxRetries:  3,
		Logger:      zerolog.Nop(),
	})
}

func TestNotifyRemediationCompleted_HappyPath(t *testing.T) {
	const secret = "rotate-me"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/webhooks/cyberpath/remediation" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Irflow-Timestamp")
		sig := strings.TrimPrefix(r.Header.Get("X-Irflow-Signature"), "sha256=")
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(ts))
		h.Write([]byte("."))
		h.Write(body)
		want := hex.EncodeToString(h.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(want)) {
			t.Errorf("bad signature: got %s want %s", sig, want)
		}
		if r.Header.Get("X-Irflow-Event-Id") == "" {
			t.Error("missing event id")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, secret)
	if err := c.NotifyRemediationCompleted(context.Background(), "inc_1", "cohort_1", time.Now()); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestNotifyRemediationCompleted_RetriesOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, "s")
	if err := c.NotifyRemediationCompleted(context.Background(), "i", "c", time.Now()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestNotifyRemediationCompleted_NoRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, "s")
	if err := c.NotifyRemediationCompleted(context.Background(), "i", "c", time.Now()); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestNotifyRemediationCompleted_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := New(Options{
		BaseURL:     url,
		HMACSecret:  "s",
		HTTPTimeout: 200 * time.Millisecond,
		MaxRetries:  1,
		Logger:      zerolog.Nop(),
	})
	if err := c.NotifyRemediationCompleted(context.Background(), "i", "c", time.Now()); err == nil {
		t.Fatal("expected transport error")
	}
}
