package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// withClaims returns a request whose context carries the supplied claims,
// simulating what Middleware would have done after a successful Verify.
func withClaims(c *Claims) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		ctx := context.WithValue(req.Context(), ctxKey{}, c)
		req = req.WithContext(ctx)
	}
	return req
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	h := RequireRole(RoleAdmin)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withClaims(&Claims{Sub: "u1", Role: RoleAdmin}))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin → admin route: want 200, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsMismatchedRole(t *testing.T) {
	h := RequireRole(RoleAdmin)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withClaims(&Claims{Sub: "u1", Role: RoleLearner}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("learner → admin route: want 403, got %d", rec.Code)
	}
}

func TestRequireRole_NoClaimsReturns401(t *testing.T) {
	h := RequireRole(RoleAdmin)(okHandler())
	rec := httptest.NewRecorder()
	// No claims in context.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: want 401, got %d", rec.Code)
	}
}

func TestRequireAnyRole_AcceptsEither(t *testing.T) {
	h := RequireAnyRole(RoleAdmin, RoleInstructor)(okHandler())

	for _, role := range []string{RoleAdmin, RoleInstructor} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withClaims(&Claims{Sub: "u1", Role: role}))
		if rec.Code != http.StatusOK {
			t.Fatalf("role=%s: want 200, got %d", role, rec.Code)
		}
	}

	// Learner is in neither set → 403.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withClaims(&Claims{Sub: "u1", Role: RoleLearner}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("learner against (admin|instructor): want 403, got %d", rec.Code)
	}
}

func TestHasRole(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
		role   string
		want   bool
	}{
		{"nil claims", nil, RoleAdmin, false},
		{"empty role arg", &Claims{Role: RoleAdmin}, "", false},
		{"single Role match", &Claims{Role: RoleAdmin}, RoleAdmin, true},
		{"single Role mismatch", &Claims{Role: RoleLearner}, RoleAdmin, false},
		{"Roles slice match", &Claims{Roles: []string{RoleInstructor, RoleAuditor}}, RoleAuditor, true},
		{"Roles slice mismatch", &Claims{Roles: []string{RoleLearner}}, RoleAdmin, false},
		{"Role + Roles, hits Role", &Claims{Role: RoleAdmin, Roles: []string{RoleLearner}}, RoleAdmin, true},
		{"Role + Roles, hits Roles", &Claims{Role: RoleLearner, Roles: []string{RoleAdmin}}, RoleAdmin, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasRole(tc.claims, tc.role); got != tc.want {
				t.Fatalf("HasRole=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestClaimsFromContext_RoundTrip(t *testing.T) {
	want := &Claims{Sub: "u1", Role: RoleInstructor}
	ctx := context.WithValue(context.Background(), ctxKey{}, want)
	got, ok := ClaimsFromContext(ctx)
	if !ok || got != want {
		t.Fatalf("ClaimsFromContext: got=%v ok=%v, want=%v true", got, ok, want)
	}

	if _, ok := ClaimsFromContext(context.Background()); ok {
		t.Fatalf("empty ctx: want ok=false")
	}
}
