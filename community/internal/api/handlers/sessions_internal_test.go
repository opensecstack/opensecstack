package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenHash_IsDeterministicSHA256(t *testing.T) {
	h1 := tokenHash("my-jwt-token")
	h2 := tokenHash("my-jwt-token")
	if h1 != h2 {
		t.Fatal("expected tokenHash to be deterministic for the same input")
	}
	// SHA-256 hex digest is always 64 chars.
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex digest, got %d chars: %s", len(h1), h1)
	}
}

func TestTokenHash_DifferentInputs_DifferentHashes(t *testing.T) {
	h1 := tokenHash("token-a")
	h2 := tokenHash("token-b")
	if h1 == h2 {
		t.Error("expected different tokens to hash differently")
	}
}

func TestRawTokenFromRequest_ValidBearer_ExtractsToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc123")

	got := rawTokenFromRequest(req)
	if got != "abc123" {
		t.Errorf("expected 'abc123', got %q", got)
	}
}

func TestRawTokenFromRequest_MissingHeader_ReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	got := rawTokenFromRequest(req)
	if got != "" {
		t.Errorf("expected empty string when Authorization header is missing, got %q", got)
	}
}

func TestRawTokenFromRequest_WrongScheme_ReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	got := rawTokenFromRequest(req)
	if got != "" {
		t.Errorf("expected empty string for non-Bearer scheme, got %q", got)
	}
}

// TokenHashForTest exposes the unexported tokenHash helper to the external
// handlers_test package (sessions_test.go), which needs to pre-compute the
// same hash the handler derives from a raw bearer token when seeding
// user_sessions rows for live-DB tests.
func TokenHashForTest(raw string) string {
	return tokenHash(raw)
}
