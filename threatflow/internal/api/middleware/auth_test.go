package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/threatflow/internal/auth"
)

func newTestService(t *testing.T) *auth.Service {
	t.Helper()
	s, err := auth.NewService(auth.Config{Secret: "test-secret-at-least-32-chars-long", TTL: time.Hour})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return s
}

func TestIdentity_NoValueInContextReturnsNil(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := Identity(req); got != nil {
		t.Errorf("Identity() = %+v, want nil", got)
	}
}

func TestContextWithIdentity_RoundTrips(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id := &auth.Identity{Subject: "apikey:foo", Role: auth.RoleOperator}
	req = req.WithContext(ContextWithIdentity(req.Context(), id))

	got := Identity(req)
	if got == nil || got.Subject != "apikey:foo" {
		t.Fatalf("Identity() = %+v, want %+v", got, id)
	}
	if got.Role != auth.RoleOperator {
		t.Errorf("Role = %q, want %q", got.Role, auth.RoleOperator)
	}
}

func TestJWTAlg_ExtractsHS256(t *testing.T) {
	svc := newTestService(t)
	tok, _, err := svc.IssueToken(&auth.Identity{Subject: "x", Role: auth.RoleViewer})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := jwtAlg(tok); got != "HS256" {
		t.Errorf("jwtAlg() = %q, want HS256", got)
	}
}

func TestJWTAlg_MalformedTokenReturnsEmpty(t *testing.T) {
	cases := []string{"", "not.a.jwt.at.all", "onlyonepart", "bad-base64.x.y"}
	for _, c := range cases {
		if got := jwtAlg(c); got != "" {
			t.Errorf("jwtAlg(%q) = %q, want empty string", c, got)
		}
	}
}

func TestRequireAuth_MissingHeaderReturns401(t *testing.T) {
	svc := newTestService(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := RequireAuth(svc)(next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if called {
		t.Error("next handler must not run when auth fails")
	}
}

func TestRequireAuth_MalformedHeaderReturns401(t *testing.T) {
	svc := newTestService(t)
	handler := RequireAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "NotBearer sometoken")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuth_ValidTokenPassesThroughAndSetsIdentity(t *testing.T) {
	svc := newTestService(t)
	tok, _, err := svc.IssueToken(&auth.Identity{Subject: "apikey:abc", Role: auth.RoleAnalyst, Source: "api_key"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var seen *auth.Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = Identity(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireAuth(svc)(next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seen == nil {
		t.Fatal("expected identity to be set in request context")
	}
	if seen.Subject != "apikey:abc" || seen.Role != auth.RoleAnalyst {
		t.Errorf("identity = %+v, want subject=apikey:abc role=analyst", seen)
	}
}

func TestRequireAuth_ExpiredTokenReturns401(t *testing.T) {
	svc, _ := auth.NewService(auth.Config{Secret: "another-32-char-secret-value-xxx", TTL: time.Millisecond})
	tok, _, _ := svc.IssueToken(&auth.Identity{Subject: "x", Role: auth.RoleViewer})
	time.Sleep(10 * time.Millisecond)

	handler := RequireAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for expired token", rec.Code)
	}
}

func TestRequireRole_InsufficientRoleReturns403(t *testing.T) {
	svc := newTestService(t)
	tok, _, _ := svc.IssueToken(&auth.Identity{Subject: "x", Role: auth.RoleViewer})

	handler := RequireRole(svc, auth.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not run when role check fails")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireRole_SufficientRolePassesThrough(t *testing.T) {
	svc := newTestService(t)
	tok, _, _ := svc.IssueToken(&auth.Identity{Subject: "x", Role: auth.RoleAdmin})

	called := false
	handler := RequireRole(svc, auth.RoleOperator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("expected next handler to run for sufficient role")
	}
}

func TestRequireRole_UnauthenticatedReturns401NotForbidden(t *testing.T) {
	svc := newTestService(t)
	handler := RequireRole(svc, auth.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (auth failure should precede role check)", rec.Code)
	}
}

// TestRequireAuth_RS256TokenWithUnreachableSinauthReturns401 exercises the
// dual-verification branch: an RS256-header token routes to sinauth instead
// of the local HS256 secret. With no sinauth server reachable at the
// configured URL, the request must fail closed with 401, not panic or hang.
func TestRequireAuth_RS256TokenWithUnreachableSinauthReturns401(t *testing.T) {
	svc := newTestService(t)
	// A syntactically valid JWT header announcing RS256, signature is irrelevant
	// since verification is delegated to (an unreachable) sinauth.
	rs256Header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"RS256","typ":"JWT"}
	fakeToken := rs256Header + ".eyJzdWIiOiJ4In0.sig"

	handler := RequireAuthWithSinauth(svc, "http://127.0.0.1:1")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not run when sinauth verification fails")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+fakeToken)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
