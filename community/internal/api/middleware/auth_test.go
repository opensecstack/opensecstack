package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/opensecstack/community/internal/auth"
)

const testSecret = "test-secret-key"

// claimsHandler is a handler that records whether claims were set in the context.
type claimsHandler struct {
	called bool
	claims *auth.Claims
}

func (h *claimsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.claims = ClaimsFrom(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestAuth_NoAuthorizationHeader_Returns401(t *testing.T) {
	next := &claimsHandler{}
	handler := Auth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if next.called {
		t.Error("next handler should not be called when no Authorization header")
	}
}

func TestAuth_MalformedBearerToken_Returns401(t *testing.T) {
	next := &claimsHandler{}
	handler := Auth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed token, got %d", rec.Code)
	}
	if next.called {
		t.Error("next handler should not be called for malformed token")
	}
}

func TestAuth_ExpiredJWT_Returns401(t *testing.T) {
	// Issue a token that expired 1 hour ago.
	claims := &auth.Claims{
		Sub:  "user1",
		Role: "author",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user1",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	next := &claimsHandler{}
	handler := Auth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", rec.Code)
	}
	if next.called {
		t.Error("next handler should not be called for expired token")
	}
}

func TestAuth_ValidJWT_CallsNextAndSetsClaims(t *testing.T) {
	tok, _, err := auth.Issue(testSecret, "test-issuer", "alice", "author", time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	next := &claimsHandler{}
	handler := Auth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid token, got %d", rec.Code)
	}
	if !next.called {
		t.Error("next handler should be called for valid token")
	}
	if next.claims == nil {
		t.Fatal("claims should be set in context for valid token")
	}
	if next.claims.Sub != "alice" {
		t.Errorf("expected Sub=alice, got %q", next.claims.Sub)
	}
	if next.claims.Role != "author" {
		t.Errorf("expected Role=author, got %q", next.claims.Role)
	}
}

func TestAuth_WrongSigningSecret_Returns401(t *testing.T) {
	// Token signed with a different secret.
	tok, _, err := auth.Issue("other-secret", "test-issuer", "alice", "author", time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	next := &claimsHandler{}
	handler := Auth(testSecret)(next) // middleware uses testSecret, token signed with other-secret

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong signing secret, got %d", rec.Code)
	}
	if next.called {
		t.Error("next handler should not be called when signing secret is wrong")
	}
}

func TestAuth_MissingBearerPrefix_Returns401(t *testing.T) {
	tok, _, err := auth.Issue(testSecret, "test-issuer", "alice", "author", time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	next := &claimsHandler{}
	handler := Auth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// Valid token but without "Bearer " prefix.
	req.Header.Set("Authorization", tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing Bearer prefix, got %d", rec.Code)
	}
}

func TestOptionalAuth_ValidToken_SetsClaims(t *testing.T) {
	tok, _, err := auth.Issue(testSecret, "test-issuer", "bob", "moderator", time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	next := &claimsHandler{}
	handler := OptionalAuth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/feed", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if next.claims == nil {
		t.Fatal("claims should be set for valid optional token")
	}
	if next.claims.Sub != "bob" {
		t.Errorf("expected Sub=bob, got %q", next.claims.Sub)
	}
}

func TestOptionalAuth_NoToken_StillCallsNext(t *testing.T) {
	next := &claimsHandler{}
	handler := OptionalAuth(testSecret)(next)

	req := httptest.NewRequest(http.MethodGet, "/feed", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !next.called {
		t.Error("next handler should always be called with OptionalAuth")
	}
	if next.claims != nil {
		t.Error("claims should be nil when no token provided")
	}
}
