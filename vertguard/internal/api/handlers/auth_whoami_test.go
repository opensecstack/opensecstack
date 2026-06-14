package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/vertguard/internal/auth"
)

// withClaims mirrors the production auth middleware's context injection
// so handler tests can exercise the post-middleware branch without
// minting a real JWT.
func withClaims(r *http.Request, c *auth.Claims) *http.Request {
	ctx := auth.InjectClaimsForTest(r.Context(), c)
	return r.WithContext(ctx)
}

func TestWhoami_NoClaims_401(t *testing.T) {
	h := NewAuthHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/whoami", nil)
	rw := httptest.NewRecorder()
	h.Whoami(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rw.Code, rw.Body.String())
	}
}

func TestWhoami_WithClaims_200(t *testing.T) {
	h := NewAuthHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/whoami", nil)
	req = withClaims(req, &auth.Claims{
		Sub: "alice", Role: "admin", Iss: "vertguard", Exp: 9999999999, Iat: 1700000000,
	})
	rw := httptest.NewRecorder()
	h.Whoami(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rw.Code, rw.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("body decode: %v", err)
	}
	if got["sub"] != "alice" || got["role"] != "admin" || got["iss"] != "vertguard" {
		t.Fatalf("body = %+v", got)
	}
	if _, ok := got["exp"]; !ok {
		t.Fatalf("exp missing from body: %+v", got)
	}
}

// silence unused-import flag when the file is built standalone.
var _ = context.Background
