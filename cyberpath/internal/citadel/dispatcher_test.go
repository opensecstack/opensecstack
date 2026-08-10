// Additional unit tests for dispatch classification helpers
// (dispatcher.go) not already exercised end-to-end by worker_test.go.
package citadel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// isCitadel4xx must classify by the presence of a space-padded status
// code substring in the error message, per the CITADEL client's error
// formatting (`citadel <code>: <body>` for 4xx, `citadel %d: ...` for
// 5xx — same shape).
func TestIsCitadel4xx(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"400 bad request", errors.New("citadel 400: bad schema"), true},
		{"404 not found", errors.New("citadel 404: not found"), true},
		{"422 unprocessable", errors.New("citadel 422: invalid"), true},
		{"408 timeout is retryable not 4xx", errors.New("citadel 408: timeout"), false},
		{"429 too many requests is retryable not 4xx", errors.New("citadel 429: slow down"), false},
		{"500 internal error", fmt.Errorf("citadel %d: %s", 500, "boom"), false},
		{"503 unavailable", errors.New("citadel 503: down"), false},
		{"transport error has no code", errors.New("connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isCitadel4xx(tc.err)
			if got != tc.want {
				t.Fatalf("isCitadel4xx(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestContainsCode(t *testing.T) {
	if !containsCode("citadel 404: not found", " 404") {
		t.Fatalf("expected match for ' 404' in 'citadel 404: not found'")
	}
	if !containsCode("citadel 4004: weird", " 400") {
		// containsCode does a plain substring search, so " 400" DOES
		// match as a prefix of " 4004" — it has no word-boundary
		// awareness. Documenting this (slightly loose) behaviour
		// rather than asserting the opposite of what the code does.
		t.Fatalf("expected substring match: ' 400' is a prefix of ' 4004'")
	}
	if containsCode("citadel 5004: weird", " 400") {
		t.Fatalf("unexpected match for ' 400' in ' 5004'")
	}
	if containsCode("short", " 40000000") {
		t.Fatalf("containsCode must return false when code is longer than s")
	}
	if containsCode("", " 400") {
		t.Fatalf("containsCode on empty string must be false")
	}
}

// dispatch must route by Destination and reject unknown values as
// non-retryable (a typo'd destination will never succeed on retry).
func TestDispatch_UnknownDestination(t *testing.T) {
	w := NewWorker(Options{
		Outbox: &fakeOutbox{},
		Logger: newTestLogger(),
	})
	err := w.dispatch(context.Background(), &OutboxEntry{Destination: "carrier-pigeon"})
	if err == nil {
		t.Fatalf("expected error for unknown destination")
	}
	if errIsRetryable(err) {
		t.Fatalf("unknown destination must be classified non-retryable")
	}
	var nr *nonRetryableError
	if !errors.As(err, &nr) {
		t.Fatalf("expected *nonRetryableError, got %T", err)
	}
}

// dispatch("both") must attempt CITADEL first; if CITADEL fails, the
// webhook leg must NOT be attempted (dispatcher.go: "return err"
// short-circuits fan-out on the first leg's failure).
func TestDispatch_Both_CitadelFailsShortCircuits(t *testing.T) {
	webhookCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hooks := &fakeWebhookStore{records: map[string]*WebhookRecord{
		"hook-1": {ID: "hook-1", URL: srv.URL, SecretHMAC: "s", Active: true},
	}}

	w := NewWorker(Options{
		Outbox:   &fakeOutbox{},
		Webhooks: hooks,
		// Citadel client is nil → dispatchCITADEL returns a retryable
		// "citadel client not configured" error immediately.
		Logger: newTestLogger(),
	})

	err := w.dispatch(context.Background(), &OutboxEntry{
		Destination: "both",
		WebhookID:   "hook-1",
		Payload:     []byte(`{}`),
	})
	if err == nil {
		t.Fatalf("expected error when CITADEL client is not configured")
	}
	if webhookCalled {
		t.Fatalf("webhook leg must not be attempted when the CITADEL leg fails first")
	}
}

// dispatch("both") succeeds only when both legs succeed.
func TestDispatch_Both_BothSucceed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hooks := &fakeWebhookStore{records: map[string]*WebhookRecord{
		"hook-1": {ID: "hook-1", URL: srv.URL, SecretHMAC: "s", Active: true},
	}}
	citadelClient := New(Config{DryRun: true}, newTestLogger())

	w := NewWorker(Options{
		Outbox:   &fakeOutbox{},
		Webhooks: hooks,
		Citadel:  citadelClient,
		Logger:   newTestLogger(),
	})

	err := w.dispatch(context.Background(), &OutboxEntry{
		Destination:   "both",
		WebhookID:     "hook-1",
		EventType:     "cyberpath.completion",
		Payload:       []byte(`{"subject":"user:1"}`),
		CorrelationID: "c-1",
	})
	if err != nil {
		t.Fatalf("expected both legs to succeed, got %v", err)
	}
}

// dispatchCITADEL: an unparseable payload must be classified
// non-retryable — a malformed JSON blob will never become parseable
// on retry, so it must go straight to DLQ instead of looping forever.
func TestDispatchCITADEL_BadPayload_NonRetryable(t *testing.T) {
	w := NewWorker(Options{
		Outbox:  &fakeOutbox{},
		Citadel: New(Config{DryRun: true}, newTestLogger()),
		Logger:  newTestLogger(),
	})
	err := w.dispatchCITADEL(context.Background(), &OutboxEntry{
		Payload: []byte(`not-json`),
	})
	if err == nil {
		t.Fatalf("expected error for malformed payload")
	}
	if errIsRetryable(err) {
		t.Fatalf("malformed payload must be non-retryable")
	}
}

// dispatchWebhook: missing WebhookID is a non-retryable configuration
// error (the row will never gain a webhook_id on retry).
func TestDispatchWebhook_MissingWebhookID(t *testing.T) {
	w := NewWorker(Options{
		Outbox:   &fakeOutbox{},
		Webhooks: &fakeWebhookStore{records: map[string]*WebhookRecord{}},
		Logger:   newTestLogger(),
	})
	err := w.dispatchWebhook(context.Background(), &OutboxEntry{Destination: "webhook"})
	if err == nil || errIsRetryable(err) {
		t.Fatalf("expected non-retryable error for missing webhook id, got %v", err)
	}
}

// dispatchWebhook: unknown webhook id is non-retryable (won't appear
// on retry either).
func TestDispatchWebhook_UnknownWebhook(t *testing.T) {
	w := NewWorker(Options{
		Outbox:   &fakeOutbox{},
		Webhooks: &fakeWebhookStore{records: map[string]*WebhookRecord{}},
		Logger:   newTestLogger(),
	})
	err := w.dispatchWebhook(context.Background(), &OutboxEntry{
		Destination: "webhook",
		WebhookID:   "missing-hook",
	})
	if err == nil || errIsRetryable(err) {
		t.Fatalf("expected non-retryable error for unknown webhook, got %v", err)
	}
}

// dispatchWebhook: inactive webhook is non-retryable — an operator
// disabled it deliberately, so it must not be silently re-attempted
// forever.
func TestDispatchWebhook_InactiveWebhook(t *testing.T) {
	w := NewWorker(Options{
		Outbox: &fakeOutbox{},
		Webhooks: &fakeWebhookStore{records: map[string]*WebhookRecord{
			"hook-1": {ID: "hook-1", URL: "http://example.invalid", Active: false},
		}},
		Logger: newTestLogger(),
	})
	err := w.dispatchWebhook(context.Background(), &OutboxEntry{
		Destination: "webhook",
		WebhookID:   "hook-1",
	})
	if err == nil || errIsRetryable(err) {
		t.Fatalf("expected non-retryable error for inactive webhook, got %v", err)
	}
}

// dispatchWebhook: the outgoing request must be correctly signed —
// the receiving side recomputes signWebhook(body, ts, secret) and
// compares against X-CyberPath-Signature.
func TestDispatchWebhook_SignsRequest(t *testing.T) {
	var gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-CyberPath-Signature")
		gotTS = r.Header.Get("X-CyberPath-Timestamp")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := NewWorker(Options{
		Outbox: &fakeOutbox{},
		Webhooks: &fakeWebhookStore{records: map[string]*WebhookRecord{
			"hook-1": {ID: "hook-1", URL: srv.URL, SecretHMAC: "topsecret", Active: true},
		}},
		Logger:      newTestLogger(),
		HTTPTimeout: 2 * time.Second,
	})
	err := w.dispatchWebhook(context.Background(), &OutboxEntry{
		Destination:   "webhook",
		WebhookID:     "hook-1",
		EventType:     "cyberpath.cohort.created",
		Payload:       []byte(`{"x":1}`),
		CorrelationID: "corr-9",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotSig == "" || gotTS == "" {
		t.Fatalf("expected signature and timestamp headers to be sent")
	}
	wantSig := "sha256=" + signWebhook(gotBody, gotTS, "topsecret")
	if gotSig != wantSig {
		t.Fatalf("signature mismatch: got %q want %q (body=%s)", gotSig, wantSig, gotBody)
	}
}
