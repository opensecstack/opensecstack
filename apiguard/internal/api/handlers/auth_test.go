package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/config"
)

// testConfig builds a *config.Config with only the auth fields populated.
func testConfig(secret string, keys ...string) *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			JWTSecret: secret,
			APIKeys:   keys,
		},
	}
}

func TestAuthToken_ValidKey(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret", "valid-key-1")
	h := NewAuth(logger, cfg)

	body := bytes.NewBufferString(`{"api_key":"valid-key-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	token, ok := result["token"]
	if !ok {
		t.Fatal("response missing 'token' key")
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}
}

func TestAuthToken_InvalidKey(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret", "valid-key-1")
	h := NewAuth(logger, cfg)

	body := bytes.NewBufferString(`{"api_key":"wrong-key"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestAuthToken_EmptyAPIKey(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret", "valid-key-1")
	h := NewAuth(logger, cfg)

	body := bytes.NewBufferString(`{"api_key":""}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Result().StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Result().StatusCode)
	}
}

func TestAuthToken_MalformedJSON(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret", "valid-key-1")
	h := NewAuth(logger, cfg)

	body := bytes.NewBufferString(`not valid json`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Result().StatusCode)
	}
}

func TestAuthToken_MissingJWTSecret(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("", "valid-key-1") // empty secret
	h := NewAuth(logger, cfg)

	body := bytes.NewBufferString(`{"api_key":"valid-key-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Result().StatusCode)
	}
}

func TestAuthToken_EmptyAPIKeysList(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret") // no api keys
	h := NewAuth(logger, cfg)

	body := bytes.NewBufferString(`{"api_key":"any-key"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Result().StatusCode)
	}
}

func TestAuthPing_Returns200WithHintField(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret", "valid-key-1")
	h := NewAuth(logger, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	w := httptest.NewRecorder()
	h.Ping(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := result["hint"]; !ok {
		t.Fatal("response missing 'hint' key")
	}
	// A-M5: 'configured' field must no longer be present to avoid leaking server state.
	if _, ok := result["configured"]; ok {
		t.Fatal("response must not contain 'configured' key (leaks server state)")
	}
}

func TestAuthPing_HasAlgorithmsField(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("supersecret", "valid-key-1")
	h := NewAuth(logger, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	w := httptest.NewRecorder()
	h.Ping(w, req)

	var result map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	algs, ok := result["algorithms"]
	if !ok {
		t.Fatal("response missing 'algorithms' key")
	}
	if algs == nil {
		t.Fatal("'algorithms' field is nil")
	}
}

func TestAuthPing_NoConfiguredFieldRegardlessOfSetup(t *testing.T) {
	logger := zerolog.Nop()
	cfg := testConfig("") // no secret, no keys
	h := NewAuth(logger, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	w := httptest.NewRecorder()
	h.Ping(w, req)

	var result map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// A-M5: 'configured' must never be present regardless of server state.
	if _, ok := result["configured"]; ok {
		t.Fatal("response must not contain 'configured' key (leaks server state)")
	}
}
