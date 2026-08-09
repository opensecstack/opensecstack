package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestNewThreatFlowClient_SetsFields(t *testing.T) {
	c := NewThreatFlowClient("http://example.invalid", "key", time.Minute, nil, zerolog.Nop())
	if c == nil {
		t.Fatal("NewThreatFlowClient returned nil")
	}
	if c.apiURL != "http://example.invalid" || c.apiKey != "key" {
		t.Errorf("apiURL/apiKey not set: %q %q", c.apiURL, c.apiKey)
	}
	if c.http == nil {
		t.Error("http client should be initialized")
	}
}

func TestThreatFlowClient_Run_EmptyAPIURLReturnsImmediately(t *testing.T) {
	c := NewThreatFlowClient("", "", time.Millisecond, nil, zerolog.Nop())
	done := make(chan struct{})
	go func() {
		c.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly for empty apiURL")
	}
}

func TestThreatFlowClient_PullOnce_UnauthorizedReturnsSpecificError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewThreatFlowClient(srv.URL, "bad-key", time.Minute, nil, zerolog.Nop())
	err := c.pullOnce(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "threatflow: upstream_auth_failed (401)" {
		t.Errorf("err = %q, want threatflow: upstream_auth_failed (401)", got)
	}
}

func TestThreatFlowClient_PullOnce_ServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewThreatFlowClient(srv.URL, "", time.Minute, nil, zerolog.Nop())
	if err := c.pullOnce(context.Background()); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestThreatFlowClient_PullOnce_ForwardsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		// Force the auth-failure branch so we never reach c.store, which is nil.
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewThreatFlowClient(srv.URL, "secret-key", time.Minute, nil, zerolog.Nop())
	_ = c.pullOnce(context.Background())
	if gotAuth != "Bearer secret-key" {
		t.Errorf("Authorization = %q, want Bearer secret-key", gotAuth)
	}
}

func TestThreatFlowClient_PushAdvisory_EmptyAPIURLErrors(t *testing.T) {
	c := NewThreatFlowClient("", "", time.Minute, nil, zerolog.Nop())
	err := c.PushAdvisory(context.Background(), map[string]any{"k": "v"})
	if err == nil {
		t.Fatal("expected error when apiURL is empty")
	}
}

func TestThreatFlowClient_PushAdvisory_Success(t *testing.T) {
	var gotPath, gotMethod, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewThreatFlowClient(srv.URL, "key", time.Minute, nil, zerolog.Nop())
	if err := c.PushAdvisory(context.Background(), map[string]any{"document": "x"}); err != nil {
		t.Fatalf("PushAdvisory: %v", err)
	}
	if gotPath != "/api/v1/advisories" {
		t.Errorf("path = %q, want /api/v1/advisories", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotContentType)
	}
}

func TestThreatFlowClient_PushAdvisory_UnauthorizedReturnsSpecificError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewThreatFlowClient(srv.URL, "", time.Minute, nil, zerolog.Nop())
	err := c.PushAdvisory(context.Background(), map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "threatflow: upstream_auth_failed (401)" {
		t.Errorf("err = %q, want threatflow: upstream_auth_failed (401)", got)
	}
}

func TestThreatFlowClient_PushAdvisory_ServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewThreatFlowClient(srv.URL, "", time.Minute, nil, zerolog.Nop())
	if err := c.PushAdvisory(context.Background(), map[string]any{}); err == nil {
		t.Fatal("expected error for 502 response")
	}
}
