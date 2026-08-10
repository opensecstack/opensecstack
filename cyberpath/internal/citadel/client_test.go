// Tests for the CITADEL HTTP client (client.go).
package citadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestClient_New_DefaultsTimeout(t *testing.T) {
	c := New(Config{}, zerolog.Nop())
	if c.http.Timeout != 5*time.Second {
		t.Fatalf("expected default timeout of 5s, got %v", c.http.Timeout)
	}

	c2 := New(Config{HTTPTimeout: 2 * time.Second}, zerolog.Nop())
	if c2.http.Timeout != 2*time.Second {
		t.Fatalf("expected configured timeout of 2s, got %v", c2.http.Timeout)
	}
}

// DryRun (or empty BaseURL) must short-circuit to nil without making
// any HTTP call — this is the standalone/dev mode contract.
func TestClient_Submit_DryRun_NoHTTPCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{DryRun: true, BaseURL: srv.URL}, zerolog.Nop())
	if err := c.Submit(context.Background(), Event{EventType: "cyberpath.completion", Subject: "user:1"}); err != nil {
		t.Fatalf("dry-run Submit returned error: %v", err)
	}
	if called {
		t.Fatalf("dry-run must not perform an HTTP call")
	}
}

// Empty BaseURL (standalone mode) must also short-circuit even when
// DryRun is false.
func TestClient_Submit_EmptyBaseURL_NoHTTPCall(t *testing.T) {
	c := New(Config{}, zerolog.Nop())
	if err := c.Submit(context.Background(), Event{EventType: "x", Subject: "y"}); err != nil {
		t.Fatalf("expected nil error for empty BaseURL, got %v", err)
	}
}

// A 2xx response is treated as success.
func TestClient_Submit_2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/worm/emit" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-CyberPath-Signature") == "" {
			t.Errorf("expected signature header to be set")
		}
		if r.Header.Get("X-CyberPath-Timestamp") == "" {
			t.Errorf("expected timestamp header to be set")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "s3cr3t"}, zerolog.Nop())
	err := c.Submit(context.Background(), Event{EventType: "cyberpath.completion", Subject: "user:1", Timestamp: time.Now()})
	if err != nil {
		t.Fatalf("expected nil error on 2xx, got %v", err)
	}
}

// A 5xx response must produce an error whose message carries the
// %d-formatted status code — dispatchCITADEL relies on this shape via
// isCitadel4xx to classify retryability.
func TestClient_Submit_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL}, zerolog.Nop())
	err := c.Submit(context.Background(), Event{EventType: "x", Subject: "y"})
	if err == nil {
		t.Fatalf("expected error on 5xx, got nil")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected error to carry status + body, got %q", err.Error())
	}
}

// A 4xx response must also error, distinctly formatted (no %d verb —
// isCitadel4xx distinguishes it from 5xx by pattern, not by a typed
// error, so we just assert the code appears in the message).
func TestClient_Submit_4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad schema"))
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL}, zerolog.Nop())
	err := c.Submit(context.Background(), Event{EventType: "x", Subject: "y"})
	if err == nil {
		t.Fatalf("expected error on 4xx, got nil")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "bad schema") {
		t.Fatalf("expected error to carry status + body, got %q", err.Error())
	}
}

// ProjectID from Config is only applied when the event doesn't
// already carry one.
func TestClient_Submit_ProjectIDDefaulting(t *testing.T) {
	var gotProjectID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ProjectID string `json:"project_id"`
		}
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotProjectID = body.ProjectID
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, ProjectID: "proj-default"}, zerolog.Nop())
	if err := c.Submit(context.Background(), Event{EventType: "x", Subject: "y"}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotProjectID != "proj-default" {
		t.Fatalf("expected default project id to be applied, got %q", gotProjectID)
	}

	// Explicit ProjectID on the event must NOT be overridden.
	if err := c.Submit(context.Background(), Event{EventType: "x", Subject: "y", ProjectID: "proj-explicit"}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotProjectID != "proj-explicit" {
		t.Fatalf("expected explicit project id to survive, got %q", gotProjectID)
	}
}

// sign() must be deterministic for identical inputs and must change
// when any of the three inputs (body, timestamp, secret) change —
// this is the HMAC scheme dispatchWebhook / dispatchCITADEL depend on
// for signature verification on the receiving side.
func TestSign_DeterministicAndSensitive(t *testing.T) {
	body := []byte(`{"a":1}`)
	s1 := sign(body, "1000", "secret-a")
	s2 := sign(body, "1000", "secret-a")
	if s1 != s2 {
		t.Fatalf("sign() must be deterministic for identical inputs")
	}
	if len(s1) != 64 { // hex-encoded SHA-256 = 32 bytes = 64 hex chars
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(s1), s1)
	}

	if s3 := sign(body, "1000", "secret-b"); s3 == s1 {
		t.Fatalf("sign() must differ when the secret changes")
	}
	if s4 := sign(body, "2000", "secret-a"); s4 == s1 {
		t.Fatalf("sign() must differ when the timestamp changes")
	}
	if s5 := sign([]byte(`{"a":2}`), "1000", "secret-a"); s5 == s1 {
		t.Fatalf("sign() must differ when the body changes")
	}
}
