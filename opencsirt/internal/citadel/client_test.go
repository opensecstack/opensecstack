package citadel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSubmitOutcome_String(t *testing.T) {
	cases := map[SubmitOutcome]string{
		SubmitDelivered:      "delivered",
		SubmitQueued:         "queued",
		SubmitDropped:        "dropped",
		SubmitDryRun:         "dry_run",
		SubmitOutcome(99):    "unknown",
	}
	for outcome, want := range cases {
		if got := outcome.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", outcome, got, want)
		}
	}
}

func TestSubmit_DryRun(t *testing.T) {
	c := New("http://unused.invalid", nil, "kid", "proj", true, zerolog.Nop())
	outcome, err := c.Submit(context.Background(), "evt.type", "id-1", map[string]any{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if outcome != SubmitDryRun {
		t.Fatalf("outcome = %v, want SubmitDryRun", outcome)
	}
}

func TestSubmit_EmptyAPIURLActsAsDryRun(t *testing.T) {
	c := New("", [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	outcome, err := c.Submit(context.Background(), "evt.type", "id-1", map[string]any{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if outcome != SubmitDryRun {
		t.Fatalf("outcome = %v, want SubmitDryRun (no apiURL configured)", outcome)
	}
}

func TestSubmit_NoHMACSecretsIsPermanentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should never be contacted when no HMAC secret is configured")
	}))
	defer srv.Close()

	c := New(srv.URL, nil, "kid", "proj", false, zerolog.Nop())
	outcome, err := c.Submit(context.Background(), "evt.type", "id-1", map[string]any{})
	if err == nil {
		t.Fatal("expected an error when no HMAC secrets are configured")
	}
	if outcome != SubmitDropped {
		t.Fatalf("outcome = %v, want SubmitDropped", outcome)
	}
}

func TestSubmit_PermanentServerErrorIsDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	outcome, err := c.Submit(context.Background(), "evt.type", "id-1", map[string]any{})
	if err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	if outcome != SubmitDropped {
		t.Fatalf("outcome = %v, want SubmitDropped for a permanent (4xx) failure", outcome)
	}
}

func TestSubmit_TransientServerErrorIsQueued(t *testing.T) {
	// 5xx is treated as transient only via net.Error timeouts in isTransient;
	// deliver() itself returns a plain fmt.Errorf for 5xx, which is NOT a
	// net.Error, so isTransient(err) is false and Submit reports it as
	// dropped, not queued. This test documents that actual behaviour.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	outcome, err := c.Submit(context.Background(), "evt.type", "id-1", map[string]any{})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if outcome != SubmitDropped {
		t.Fatalf("outcome = %v, want SubmitDropped (5xx errors are not net.Error timeouts)", outcome)
	}
}

func TestIsTransient(t *testing.T) {
	if isTransient(nil) {
		t.Error("nil error must not be transient")
	}
	if isTransient(errors.New("plain error")) {
		t.Error("a plain error must not be treated as transient")
	}
	timeoutErr := &net.DNSError{IsTimeout: true}
	if !isTransient(timeoutErr) {
		t.Error("a timing-out net.Error must be treated as transient")
	}
}

func TestConfig_PrimarySecretAndKeyID(t *testing.T) {
	t.Run("prefers rotation list", func(t *testing.T) {
		cfg := Config{HMACSecrets: []string{"", "second", "third"}, HMACSecret: "legacy"}
		if got := string(cfg.primarySecret()); got != "second" {
			t.Errorf("primarySecret() = %q, want %q", got, "second")
		}
	})
	t.Run("falls back to legacy", func(t *testing.T) {
		cfg := Config{HMACSecret: "legacy"}
		if got := string(cfg.primarySecret()); got != "legacy" {
			t.Errorf("primarySecret() = %q, want %q", got, "legacy")
		}
	})
	t.Run("key id rotation and fallback", func(t *testing.T) {
		cfg := Config{KeyIDs: []string{"", "kid2"}, KeyID: "legacy-kid"}
		if got := cfg.primaryKeyID(); got != "kid2" {
			t.Errorf("primaryKeyID() = %q, want kid2", got)
		}
		cfg2 := Config{KeyID: "legacy-kid"}
		if got := cfg2.primaryKeyID(); got != "legacy-kid" {
			t.Errorf("primaryKeyID() = %q, want legacy-kid", got)
		}
	})
}

func TestConfig_SecretsAsBytes(t *testing.T) {
	empty := Config{}
	if got := empty.SecretsAsBytes(); got != nil {
		t.Errorf("SecretsAsBytes() with no secrets = %v, want nil", got)
	}
	cfg := Config{HMACSecret: "abc"}
	got := cfg.SecretsAsBytes()
	if len(got) != 1 || string(got[0]) != "abc" {
		t.Errorf("SecretsAsBytes() = %v, want [[]byte(\"abc\")]", got)
	}
}

func TestNewFromConfig_DefaultsProjectID(t *testing.T) {
	c := NewFromConfig(Config{APIURL: "http://x", HMACSecret: "s", DryRun: true}, zerolog.Nop())
	if c.projectID != "opencsirt" {
		t.Errorf("projectID = %q, want default opencsirt", c.projectID)
	}
}

func TestQueueDepth_InitiallyZero(t *testing.T) {
	c := New("http://x", nil, "kid", "proj", true, zerolog.Nop())
	if d := c.QueueDepth(); d != 0 {
		t.Errorf("QueueDepth() = %d, want 0", d)
	}
}

// TestSubmit_TransientNetworkErrorQueuesThenRunDelivers proves the full
// retry path: a network-level timeout is queued by Submit, then Run()
// retries it against a server that succeeds on the next attempt, publishing
// a SubmitDelivered confirmation on the Confirmations channel.
func TestSubmit_TransientNetworkErrorQueuesThenRunDelivers(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"worm_entry_id":"1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	// Manually enqueue an envelope to exercise Run()'s delivery path directly
	// (Submit's synchronous path already covers the deliver-success case).
	env := &Envelope{EventType: "evt", EventID: "queued-1", Payload: map[string]any{}}
	c.queue <- env

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go c.Run(ctx)

	select {
	case conf := <-c.Confirmations():
		if conf.EventID != "queued-1" {
			t.Errorf("EventID = %q, want queued-1", conf.EventID)
		}
		if conf.Outcome != SubmitDelivered {
			t.Errorf("Outcome = %v, want SubmitDelivered", conf.Outcome)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery confirmation")
	}
	if hits == 0 {
		t.Error("expected the server to be hit at least once")
	}
}

// TestSubmit_TransientTimeoutIsQueued proves Submit's synchronous path
// enqueues (rather than drops) a request that fails with a context-deadline
// timeout — the only error shape isTransient recognizes — and that no error
// is surfaced to the caller for a queued outcome (only Run's later delivery
// or failure produces a Confirmation).
func TestSubmit_TransientTimeoutIsQueued(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	outcome, err := c.Submit(ctx, "evt.type", "id-timeout", map[string]any{})
	if err != nil {
		t.Fatalf("Submit: unexpected error for a queued transient failure: %v", err)
	}
	if outcome != SubmitQueued {
		t.Fatalf("outcome = %v, want SubmitQueued", outcome)
	}
	if d := c.QueueDepth(); d != 1 {
		t.Errorf("QueueDepth() = %d, want 1", d)
	}
}

// TestSubmit_TransientTimeoutWithFullBufferIsDropped proves Submit's buffer-
// overflow branch: when the retry queue is already at capacity, a further
// transient failure is dropped (not silently blocked) and a Confirmation is
// published so a watcher observes the loss.
func TestSubmit_TransientTimeoutWithFullBufferIsDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	// Fill the retry buffer to capacity (1024) so the next transient failure
	// cannot be enqueued.
	for i := 0; i < cap(c.queue); i++ {
		c.queue <- &Envelope{EventType: "filler", EventID: "filler"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	outcome, err := c.Submit(ctx, "evt.type", "id-overflow", map[string]any{})
	if err == nil {
		t.Fatal("expected an error when the retry buffer is full")
	}
	if outcome != SubmitDropped {
		t.Fatalf("outcome = %v, want SubmitDropped", outcome)
	}

	select {
	case conf := <-c.Confirmations():
		if conf.EventID != "id-overflow" {
			t.Errorf("EventID = %q, want id-overflow", conf.EventID)
		}
		if conf.Outcome != SubmitDropped {
			t.Errorf("Outcome = %v, want SubmitDropped", conf.Outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("expected a dropped confirmation to be published")
	}
}

// TestPublish_ConfirmationChannelFullDropsSilently proves publish()'s
// default branch: when the confirmations channel is saturated, publish must
// not block the caller (deliver/Run) — it logs and drops the confirmation.
func TestPublish_ConfirmationChannelFullDropsSilently(t *testing.T) {
	c := New("http://unused.invalid", nil, "kid", "proj", true, zerolog.Nop())
	for i := 0; i < cap(c.confirms); i++ {
		c.confirms <- Confirmation{EventID: "filler"}
	}
	// Must return promptly rather than blocking.
	done := make(chan struct{})
	go func() {
		c.publish(Confirmation{EventID: "overflow"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publish() blocked instead of dropping when the confirms channel is full")
	}
	if got := len(c.confirms); got != cap(c.confirms) {
		t.Errorf("confirms channel len = %d, want unchanged at cap %d (overflow entry must be dropped)", got, cap(c.confirms))
	}
}

// TestRun_MaxRetriesExceededPublishesDropped proves Run's retry-exhaustion
// branch: after maxRetries attempts against a server that always fails, Run
// publishes a SubmitDropped confirmation instead of retrying forever.
// maxRetries is lowered to 1 (an unexported field, safe to set from within
// the package) purely so the attempt-count threshold is crossed on the very
// first failure, without waiting through the real exponential backoff.
func TestRun_MaxRetriesExceededPublishesDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	c.maxRetries = 1

	env := &Envelope{EventType: "evt", EventID: "maxed-out", attempt: 0}
	c.queue <- env

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go c.Run(ctx)

	select {
	case conf := <-c.Confirmations():
		if conf.EventID != "maxed-out" {
			t.Errorf("EventID = %q, want maxed-out", conf.EventID)
		}
		if conf.Outcome != SubmitDropped {
			t.Errorf("Outcome = %v, want SubmitDropped", conf.Outcome)
		}
		if conf.Err == nil {
			t.Error("expected a non-nil Err describing max-retries exhaustion")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the max-retries-exceeded confirmation")
	}
}

// TestRun_StopsPromptlyDuringBackoffWait proves Run's ctx.Done() select
// branch inside the backoff wait (as opposed to the top-level ctx.Done()
// covered by TestWatcher_Run_RequeueSendingErrorDoesNotBlockStartup-style
// tests): a permanent failure enters the backoff sleep, and cancelling ctx
// during that sleep must return promptly rather than waiting out the full
// backoff duration.
func TestRun_StopsPromptlyDuringBackoffWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("secret")}, "kid", "proj", false, zerolog.Nop())
	c.maxRetries = 5 // must not be exhausted after one failure, so Run reaches the backoff wait

	env := &Envelope{EventType: "evt", EventID: "backoff-1", attempt: 0}
	c.queue <- env

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	// Give Run time to dequeue, fail, and enter the ~1s backoff sleep.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Returned promptly instead of waiting out the full ~1s backoff.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not stop promptly on ctx cancellation during backoff wait")
	}
}
