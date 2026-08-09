package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

const mwSecret = "mw-test-secret"

func tokenFor(t *testing.T, role string) string {
	t.Helper()
	tok, err := Issue(mwSecret, Claims{Subject: "u", Role: role}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func protectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := ClaimsFromContext(r.Context())
		if c == nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("missing claims in context"))
			return
		}
		_, _ = w.Write([]byte(c.Subject + ":" + c.Role))
	})
}

func TestMiddleware_AcceptsValidToken(t *testing.T) {
	h := Middleware(Config{Secret: mwSecret})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, RoleOperator))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "u:operator" {
		t.Errorf("body = %q, want 'u:operator'", rec.Body.String())
	}
}

func TestMiddleware_RejectsMissingToken(t *testing.T) {
	h := Middleware(Config{Secret: mwSecret})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header not set")
	}
}

func TestMiddleware_RejectsInvalidSignature(t *testing.T) {
	// Sign with a different secret.
	badTok, _ := Issue("other-secret", Claims{Subject: "x", Role: RoleAdmin}, time.Hour)
	h := Middleware(Config{Secret: mwSecret})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+badTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_RejectsUnknownRole(t *testing.T) {
	tok, _ := Issue(mwSecret, Claims{Subject: "x", Role: "wizard"}, time.Hour)
	h := Middleware(Config{Secret: mwSecret})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestMiddleware_DisabledInjectsSyntheticAdminClaims(t *testing.T) {
	h := Middleware(Config{Disabled: true})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Disabled mode injects a synthetic (dev, admin) claim so downstream
	// RBAC guards also pass — the whole stack behaves as fully-open.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "dev:admin" {
		t.Errorf("body = %q, want 'dev:admin'", rec.Body.String())
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"valid bearer", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"missing header", "", ""},
		{"wrong scheme", "Basic abc123", ""},
		{"extra whitespace trimmed", "Bearer   spaced-token  ", "spaced-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			if got := BearerToken(req); got != c.want {
				t.Errorf("BearerToken() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRequireApprove_RoleGuardsEnforced(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware(Config{Secret: mwSecret}))
	r.With(RequireApprove()).Post("/approve", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		role string
		want int
	}{
		{RoleAdmin, http.StatusOK},
		{RoleOperator, http.StatusOK},
		{RoleVerifier, http.StatusOK},
		{RoleService, http.StatusOK},
		{RoleViewer, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/approve", nil)
			req.Header.Set("Authorization", "Bearer "+tokenFor(t, c.role))
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("role %s: status = %d, want %d", c.role, rec.Code, c.want)
			}
		})
	}
}

func TestRequireApprove_RejectsUnauthenticated(t *testing.T) {
	h := RequireApprove()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/approve", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// End-to-end test through chi router exercising RequireWrite/RequireDelete.
func TestRBAC_RoleGuardsEnforced(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware(Config{Secret: mwSecret}))

	r.With(RequireWrite()).Post("/write", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	r.With(RequireDelete()).Delete("/danger", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.With(RequireRole(RoleAdmin)).Get("/admin-only", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		name   string
		role   string
		method string
		path   string
		want   int
	}{
		{"viewer cannot write", RoleViewer, http.MethodPost, "/write", http.StatusForbidden},
		{"operator can write", RoleOperator, http.MethodPost, "/write", http.StatusCreated},
		{"admin can write", RoleAdmin, http.MethodPost, "/write", http.StatusCreated},
		{"service can write", RoleService, http.MethodPost, "/write", http.StatusCreated},
		{"verifier cannot write", RoleVerifier, http.MethodPost, "/write", http.StatusForbidden},
		{"operator cannot delete", RoleOperator, http.MethodDelete, "/danger", http.StatusForbidden},
		{"admin can delete", RoleAdmin, http.MethodDelete, "/danger", http.StatusNoContent},
		{"non-admin hits admin-only", RoleOperator, http.MethodGet, "/admin-only", http.StatusForbidden},
		{"admin hits admin-only", RoleAdmin, http.MethodGet, "/admin-only", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			req.Header.Set("Authorization", "Bearer "+tokenFor(t, c.role))
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("%s %s as %s: status = %d, want %d (body: %s)",
					c.method, c.path, c.role, rec.Code, c.want, rec.Body.String())
			}
		})
	}
}
