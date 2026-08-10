package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestHealthHandler_Health(t *testing.T) {
	logger := zerolog.Nop()
	h := NewHealth(logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}

	status, ok := body["status"]
	if !ok {
		t.Fatal("response missing 'status' key")
	}
	if status != "ok" {
		t.Fatalf("expected status 'ok', got %q", status)
	}
}

func TestHealthHandler_HealthResponseFields(t *testing.T) {
	logger := zerolog.Nop()
	h := NewHealth(logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}

	for _, key := range []string{"status", "timestamp", "uptime"} {
		if _, ok := body[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

// TestHealthHandler_UptimeIsNonEmpty verifies that the uptime field is present
// and non-empty. The health handler returns uptime as a human-readable duration
// string (e.g. "0s"), not a numeric seconds count.
func TestHealthHandler_UptimeIsNonEmpty(t *testing.T) {
	logger := zerolog.Nop()
	h := NewHealth(logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}

	uptime, ok := body["uptime"]
	if !ok {
		t.Fatal("response missing 'uptime' key")
	}
	uptimeStr, isStr := uptime.(string)
	if !isStr {
		t.Fatalf("expected 'uptime' to be a string, got %T", uptime)
	}
	if uptimeStr == "" {
		t.Fatal("'uptime' field must not be empty")
	}
}

func TestHealthHandler_Version(t *testing.T) {
	logger := zerolog.Nop()
	h := NewHealth(logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/version", nil)
	w := httptest.NewRecorder()
	h.Version(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}

	for _, key := range []string{"version", "go_version"} {
		if _, ok := body[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

func TestHealthHandler_VersionHasGitCommit(t *testing.T) {
	logger := zerolog.Nop()
	h := NewHealth(logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/version", nil)
	w := httptest.NewRecorder()
	h.Version(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}

	if _, ok := body["git_commit"]; !ok {
		t.Fatal("response missing 'git_commit' key")
	}
}

func TestHealthHandler_VersionHasGoVersion(t *testing.T) {
	logger := zerolog.Nop()
	h := NewHealth(logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/version", nil)
	w := httptest.NewRecorder()
	h.Version(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}

	goVer, ok := body["go_version"]
	if !ok {
		t.Fatal("response missing 'go_version' key")
	}
	if goVerStr, isStr := goVer.(string); !isStr || goVerStr == "" {
		t.Fatalf("expected non-empty string for 'go_version', got %v", goVer)
	}
}
