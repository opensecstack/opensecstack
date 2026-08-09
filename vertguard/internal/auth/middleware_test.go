package auth

import (
	"context"
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

func TestClaimsFromContext(t *testing.T) {
	// Missing claims: ok must be false and claims nil.
	c, ok := ClaimsFromContext(context.Background())
	if ok || c != nil {
		t.Fatalf("empty context: got claims=%v ok=%v, want nil,false", c, ok)
	}

	want := &Claims{Sub: "u1", Role: RoleOperator}
	ctx := InjectClaimsForTest(context.Background(), want)
	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatalf("expected ok=true after InjectClaimsForTest")
	}
	if got != want {
		t.Fatalf("ClaimsFromContext returned different pointer/value: %v", got)
	}
}

func finalOK() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func TestRequireWrite(t *testing.T) {
	cases := []struct {
		name       string
		claims     *Claims
		wantStatus int
	}{
		{"no claims", nil, http.StatusForbidden},
		{"admin allowed", &Claims{Role: RoleAdmin}, http.StatusOK},
		{"operator allowed", &Claims{Role: RoleOperator}, http.StatusOK},
		{"service allowed", &Claims{Role: RoleService}, http.StatusOK},
		{"viewer denied", &Claims{Role: RoleViewer}, http.StatusForbidden},
		{"verifier denied", &Claims{Role: RoleVerifier}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := RequireWrite(finalOK())
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			if c.claims != nil {
				req = req.WithContext(InjectClaimsForTest(req.Context(), c.claims))
			}
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != c.wantStatus {
				t.Fatalf("status=%d, want %d (body=%s)", rr.Code, c.wantStatus, rr.Body.String())
			}
			if c.wantStatus == http.StatusForbidden && !strings.Contains(rr.Body.String(), `"code":"forbidden"`) {
				t.Fatalf("body missing forbidden code: %s", rr.Body.String())
			}
		})
	}
}

func TestRequireAdmin(t *testing.T) {
	cases := []struct {
		name       string
		claims     *Claims
		wantStatus int
	}{
		{"no claims", nil, http.StatusForbidden},
		{"admin allowed", &Claims{Role: RoleAdmin}, http.StatusOK},
		{"operator denied", &Claims{Role: RoleOperator}, http.StatusForbidden},
		{"service denied", &Claims{Role: RoleService}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := RequireAdmin(finalOK())
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			if c.claims != nil {
				req = req.WithContext(InjectClaimsForTest(req.Context(), c.claims))
			}
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != c.wantStatus {
				t.Fatalf("status=%d, want %d (body=%s)", rr.Code, c.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestRequireRead(t *testing.T) {
	cases := []struct {
		name       string
		claims     *Claims
		wantStatus int
	}{
		{"no claims", nil, http.StatusForbidden},
		{"viewer allowed", &Claims{Role: RoleViewer}, http.StatusOK},
		{"unknown role denied", &Claims{Role: "bogus"}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := RequireRead(finalOK())
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if c.claims != nil {
				req = req.WithContext(InjectClaimsForTest(req.Context(), c.claims))
			}
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != c.wantStatus {
				t.Fatalf("status=%d, want %d (body=%s)", rr.Code, c.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestMiddleware_MissingAuthHeaderReturns401(t *testing.T) {
	h := newAuthedRouter(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("body missing unauthorized code: %s", rr.Body.String())
	}
}

func TestMiddleware_DevModeInjectsAdminClaims(t *testing.T) {
	v := NewVerifier(mwSecret, mwIssuer)
	logger := zerolog.New(io.Discard)
	mw := Middleware(v, true, &logger)
	var gotClaims *Claims
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mw(final)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if gotClaims == nil || gotClaims.Role != RoleAdmin || gotClaims.Sub != "dev" {
		t.Fatalf("devMode claims = %+v, want admin/dev", gotClaims)
	}
}

func TestJsonEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`hello`, `hello`},
		{`he said "hi"`, `he said \"hi\"`},
		{"line1\nline2", `line1\nline2`},
		{"a\\b", `a\\b`},
		{"tab\tend", `tab\tend`},
		{"ctrl\x01char", "ctrlchar"}, // control chars below 0x20 are dropped
	}
	for _, c := range cases {
		if got := jsonEscape(c.in); got != c.want {
			t.Errorf("jsonEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
