package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api"
	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

func testDeps(devMode bool) api.Deps {
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: dataplane.NewNoopClient(),
		NodeName: "test", Logger: zerolog.Nop(),
	})
	return api.Deps{
		Health:   &handlers.Health{},
		Rules:    &handlers.Rules{Service: svc, Logger: zerolog.Nop()},
		Verifier: auth.NewHS256Verifier([]string{"secret"}, "openscrub"),
		DevMode:  devMode,
		Logger:   zerolog.Nop(),
	}
}

// TestHealthAndReadyzUnauthenticated proves the liveness/readiness
// routes are reachable with zero Authorization header even outside dev
// mode — a regression here would take Kubernetes probes down along
// with real traffic.
func TestHealthAndReadyzUnauthenticated(t *testing.T) {
	r := api.NewRouter(testDeps(false))

	for _, path := range []string{"/api/v1/health", "/api/v1/readyz"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200 unauthenticated", path, rec.Code)
		}
	}
}

// TestRulesRequiresAuthOutsideDevMode confirms the authenticated API
// group actually enforces the auth middleware: with DevMode=false and
// no bearer token, protected routes must 401, not fall through.
func TestRulesRequiresAuthOutsideDevMode(t *testing.T) {
	r := api.NewRouter(testDeps(false))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 without a token outside dev mode", rec.Code)
	}
}

// TestRulesMutateRequiresOperatorRole confirms RBAC: a readonly caller
// may list but not create rules.
func TestRulesMutateRequiresOperatorRole(t *testing.T) {
	r := api.NewRouter(testDeps(false))
	issuer := auth.NewIssuer("secret", "openscrub", time.Hour)
	tok, _, err := issuer.Mint("viewer-1", auth.RoleReadOnly)
	if err != nil {
		t.Fatal(err)
	}

	// GET is allowed for readonly.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly GET /rules: got %d, want 200", rec.Code)
	}

	// POST must be forbidden for readonly.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly POST /rules: got %d, want 403", rec.Code)
	}
}

// TestAuthLoginRouteOnlyRegisteredWhenAuthSet ensures the router
// doesn't register /auth/login (404, not a panic/500) when Deps.Auth
// is nil — the zero-value Deps case used by tests that don't exercise
// login.
func TestAuthLoginRouteOnlyRegisteredWhenAuthNil(t *testing.T) {
	d := testDeps(true)
	d.Auth = nil
	r := api.NewRouter(d)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404 when Auth is nil", rec.Code)
	}
}

// panicPinger implements handlers.Pinger and panics on Ping — used to
// drive a real handler-originated panic through the full router so we
// can exercise the unexported quietRecoverer middleware.
type panicPinger struct{}

func (panicPinger) Ping(context.Context) error {
	panic("simulated db driver panic")
}

// TestPanicRecoveredAsJSON500 drives a handler panic through the full
// router (quietRecoverer is unexported, this is the only way to reach
// it) and asserts it degrades to a structured 500 instead of crashing
// the process or leaking a stack trace in the body.
func TestPanicRecoveredAsJSON500(t *testing.T) {
	d := testDeps(true)
	d.Health = &handlers.Health{DB: panicPinger{}}
	r := api.NewRouter(d)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 after handler panic", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !contains(body, `"internal server error"`) {
		t.Fatalf("expected generic error message in body, got %q", body)
	}
	// Must NOT leak stack frames / file paths into the response body.
	if contains(body, ".go:") {
		t.Fatalf("response body appears to leak a stack trace: %q", body)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
