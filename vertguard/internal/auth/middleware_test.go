package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// stubRevoker implements the Revoker interface for middleware tests.
type stubRevoker struct {
	revoked bool
	reason  string
}

func (s stubRevoker) IsRevoked(_ *Claims) (bool, string) {
	return s.revoked, s.reason
}

const mwSecret = "test-secret-key-32bytes-min-padding"
const mwIssuer = "vertguard-test"

func newAuthedRouter(t *testing.T, revoker Revoker) http.Handler {
	t.Helper()
	v := NewVerifier(mwSecret, mwIssuer)
	logger := zerolog.New(io.Discard)
	mw := Middleware(v, false, &logger, revoker)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mw(final)
}

func TestMiddleware_NilRevokerLetsValidTokenThrough(t *testing.T) {
	h := newAuthedRouter(t, nil)
	tok := mintHS256(t, mwSecret, RoleAdmin, mwIssuer, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddleware_RevokerReturns401TokenRevoked(t *testing.T) {
	h := newAuthedRouter(t, stubRevoker{revoked: true, reason: "compromised"})
	tok := mintHS256(t, mwSecret, RoleAdmin, mwIssuer, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"code":"token_revoked"`) {
		t.Fatalf("body missing token_revoked code: %s", body)
	}
	if !strings.Contains(body, "compromised") {
		t.Fatalf("body missing reason: %s", body)
	}
}

func TestMiddleware_RevokerFalseDoesNotBlock(t *testing.T) {
	h := newAuthedRouter(t, stubRevoker{revoked: false})
	tok := mintHS256(t, mwSecret, RoleAdmin, mwIssuer, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}
