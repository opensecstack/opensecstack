package citadel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSubmitOutcomeString(t *testing.T) {
	tests := []struct {
		o    SubmitOutcome
		want string
	}{
		{SubmitDelivered, "delivered"},
		{SubmitQueued, "queued"},
		{SubmitDropped, "dropped"},
		{SubmitDryRun, "dry_run"},
		{SubmitOutcome(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.o.String(); got != tt.want {
			t.Errorf("SubmitOutcome(%d).String() = %q, want %q", tt.o, got, tt.want)
		}
	}
}

func TestQueueDepthReflectsPendingItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: time.Second}, zerolog.Nop())
	if c.QueueDepth() != 0 {
		t.Fatalf("QueueDepth() = %d before any submit, want 0", c.QueueDepth())
	}
	if _, err := c.Submit(context.Background(), map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if c.QueueDepth() != 1 {
		t.Fatalf("QueueDepth() = %d after one transient submit, want 1", c.QueueDepth())
	}
}

func TestPrimarySecretPrefersRotationSlotOverLegacy(t *testing.T) {
	c := New(Config{
		HMACSecret:  "legacy",
		KeyID:       "legacy-kid",
		HMACSecrets: []string{"primary-secret", "next-secret"},
		KeyIDs:      []string{"primary-kid", "next-kid"},
	}, zerolog.Nop())
	secret, kid := c.primarySecret()
	if secret != "primary-secret" || kid != "primary-kid" {
		t.Fatalf("primarySecret() = (%q, %q), want (primary-secret, primary-kid)", secret, kid)
	}
}

func TestPrimarySecretSkipsEmptyRotationEntries(t *testing.T) {
	c := New(Config{
		HMACSecrets: []string{"", "second-secret"},
		KeyIDs:      []string{"unused", "second-kid"},
	}, zerolog.Nop())
	secret, kid := c.primarySecret()
	if secret != "second-secret" || kid != "second-kid" {
		t.Fatalf("primarySecret() = (%q, %q), want (second-secret, second-kid)", secret, kid)
	}
}

func TestPrimarySecretFallsBackToLegacyWhenNoRotationSlots(t *testing.T) {
	c := New(Config{HMACSecret: "legacy", KeyID: "legacy-kid"}, zerolog.Nop())
	secret, kid := c.primarySecret()
	if secret != "legacy" || kid != "legacy-kid" {
		t.Fatalf("primarySecret() = (%q, %q), want (legacy, legacy-kid)", secret, kid)
	}
}

func TestPrimarySecretMissingKeyIDFallsBackToScalar(t *testing.T) {
	// HMACSecrets[0] present but KeyIDs has no matching entry -> scalar
	// KeyID is used as the fallback.
	c := New(Config{
		HMACSecrets: []string{"primary-secret"},
		KeyID:       "scalar-kid",
	}, zerolog.Nop())
	secret, kid := c.primarySecret()
	if secret != "primary-secret" || kid != "scalar-kid" {
		t.Fatalf("primarySecret() = (%q, %q), want (primary-secret, scalar-kid)", secret, kid)
	}
}

func TestTransientErrorUnwrap(t *testing.T) {
	inner := errors.New("boom")
	te := transientError{err: inner}
	if te.Error() != "boom" {
		t.Fatalf("Error() = %q, want boom", te.Error())
	}
	if !errors.Is(te, inner) {
		t.Fatal("expected errors.Is to see through transientError via Unwrap")
	}
	if !isTransient(te) {
		t.Fatal("isTransient(te) = false")
	}
	if isTransient(inner) {
		t.Fatal("isTransient on a plain error should be false")
	}
}

// TestRetryLoopDeliversAfterServerRecovers proves the end-to-end retry
// path: a transient 5xx queues the event, StartRetryLoop drains it, and
// once the server recovers a DeliveryConfirmation{Delivered:true} is
// published on Confirmations().
func TestRetryLoopDeliversAfterServerRecovers(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{
		BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: time.Second,
		RetryBaseDelay: 10 * time.Millisecond, RetryMaxDelay: 20 * time.Millisecond,
		MaxRetries: 5,
	}, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.StartRetryLoop(ctx)

	out, err := c.Submit(ctx, map[string]any{"id": "evt-1", "type": "openscrub.test"})
	if err != nil {
		t.Fatalf("initial submit: %v", err)
	}
	if out != SubmitQueued {
		t.Fatalf("expected SubmitQueued, got %v", out)
	}

	// Let the server start succeeding, then wait for confirmation.
	failing.Store(false)
	select {
	case conf := <-c.Confirmations():
		if !conf.Delivered {
			t.Fatalf("expected Delivered=true, got %+v", conf)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for delivery confirmation")
	}
}

// TestRetryLoopDropsAfterMaxRetries proves a permanently-failing
// endpoint eventually produces a Delivered:false confirmation instead
// of retrying forever.
func TestRetryLoopDropsAfterMaxRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(Config{
		BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: time.Second,
		RetryBaseDelay: 5 * time.Millisecond, RetryMaxDelay: 10 * time.Millisecond,
		MaxRetries: 2,
	}, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.StartRetryLoop(ctx)

	out, err := c.Submit(ctx, map[string]any{"id": "evt-2", "type": "openscrub.test"})
	if err != nil {
		t.Fatalf("initial submit: %v", err)
	}
	if out != SubmitQueued {
		t.Fatalf("expected SubmitQueued, got %v", out)
	}

	select {
	case conf := <-c.Confirmations():
		if conf.Delivered {
			t.Fatalf("expected Delivered=false after exhausting retries, got %+v", conf)
		}
		if conf.Err == nil {
			t.Fatal("expected a non-nil Err on the terminal failure confirmation")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for the terminal failure confirmation")
	}
}
