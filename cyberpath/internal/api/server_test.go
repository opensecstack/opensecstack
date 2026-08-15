package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/api/handlers"
	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/config"
	"github.com/opensecstack/cyberpath/internal/metrics"
)

func newTestRouter(t *testing.T) *chi.Mux {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.DevMode = true
	return NewRouter(Options{
		Config:  cfg,
		Logger:  nil,
		Pinger:  nil,
		Metrics: metrics.New(),
	})
}

func TestRouterRegistersExpectedRoutes(t *testing.T) {
	r := newTestRouter(t)

	expected := []struct {
		method string
		path   string
	}{
		{"GET", "/healthz"},
		{"GET", "/readyz"},
		{"GET", "/version"},
		{"GET", "/api/v1/tracks"},
		{"GET", "/api/v1/tracks/phishing-recognition"},
		{"GET", "/api/v1/tracks/phishing-recognition/modules"},
		{"GET", "/api/v1/lessons/abc"},
		{"POST", "/api/v1/lessons/abc/complete"},
		{"POST", "/api/v1/quizzes/q1/submit"},
		{"POST", "/api/v1/labs/l1/start"},
		{"GET", "/api/v1/labs/l1/status"},
		{"GET", "/api/v1/users/u1/progress"},
		{"GET", "/api/v1/users/u1/certifications"},
		{"GET", "/api/v1/coverage/u1"},
		{"GET", "/api/v1/cyberpath/recommend?gap=art21_g"},
	}
	for _, e := range expected {
		req := httptest.NewRequest(e.method, e.path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("route %s %s not registered (status=%d)", e.method, e.path, rr.Code)
		}
	}
}

// fullyWiredOptions returns an Options struct with every handler-shaped
// field populated by a non-nil (zero-value where the constructor isn't
// needed for registration) pointer. NewRouter only takes the address of
// each handler's methods when wiring routes — it never invokes them at
// registration time — so zero-value handler structs are sufficient to
// exercise every "wired" branch in NewRouter without needing live DB
// stores or fully satisfied handler dependencies.
func fullyWiredOptions(t *testing.T) Options {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.Secret = "test-secret-at-least-this-long-enough"
	logger := zerolog.Nop()

	authHandlers, err := handlers.NewAuthHandlers(handlers.AuthDeps{
		Users:    fakeUserStore{},
		Sessions: fakeSessionStore{},
		Issuer:   mustIssuer(t),
	})
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}

	return Options{
		Config:   cfg,
		Logger:   &logger,
		Pinger:   fakePinger{},
		Metrics:  metrics.New(),
		Verifier: auth.NewHS256Verifier([]string{cfg.Auth.Secret}, "cyberpath"),

		NIS2: fakeNIS2Checker{},

		Auth:          authHandlers,
		IRFlowWebhook: handlers.NewIRFlowWebhookHandler(handlers.IRFlowWebhookOptions{}),
		Coverage:      handlers.NewCoverageHandler(&logger),
		ContentAdmin:  handlers.NewContentAdminHandler(nil, &logger),

		Tracks:      &handlers.TracksHandler{},
		Lessons:     &handlers.LessonsHandler{},
		Quizzes:     &handlers.QuizHandler{},
		Labs:        &handlers.LabsHandler{},
		Users:       &handlers.UsersHandler{},
		Enrollments: &handlers.EnrollmentHandler{},

		Terminal: &handlers.TerminalHandler{},

		Certifications: &handlers.CertificationsHandler{},

		ContentVersions: &handlers.ContentVersionsHandler{},
	}
}

type fakePinger struct{}

func (fakePinger) Ping(ctx context.Context) error { return nil }

type fakeNIS2Checker struct{}

func (fakeNIS2Checker) Health(ctx context.Context) (bool, error) { return true, nil }

type fakeUserStore struct{}

func (fakeUserStore) FindByEmail(ctx context.Context, email string) (*handlers.User, error) {
	return nil, handlers.ErrUserNotFound
}
func (fakeUserStore) FindByID(ctx context.Context, id string) (*handlers.User, error) {
	return nil, handlers.ErrUserNotFound
}
func (fakeUserStore) UpdatePasswordHash(ctx context.Context, userID, newHash string) error { return nil }

type fakeSessionStore struct{}

func (fakeSessionStore) Create(s auth.Session) error                        { return nil }
func (fakeSessionStore) GetByRefreshToken(refreshToken string) (*auth.Session, error) {
	return nil, auth.ErrSessionNotFound
}
func (fakeSessionStore) Revoke(sessionID string) error    { return nil }
func (fakeSessionStore) RevokeAll(userID string) error    { return nil }
func (fakeSessionStore) Validate(refreshToken string) (*auth.Session, error) {
	return nil, auth.ErrSessionNotFound
}

func mustIssuer(t *testing.T) *auth.Issuer {
	t.Helper()
	iss, err := auth.NewIssuer(auth.IssuerConfig{SigningKey: []byte("test-signing-key-thats-long-enough")})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

// TestRouterFullyWired_RoutesRegistered exercises the "handler wired"
// branch of every conditional in NewRouter — the mirror image of
// TestRouterRegistersExpectedRoutes, which only exercises the v0.0.1
// stub fallbacks (nil handler fields).
func TestRouterFullyWired_RoutesRegistered(t *testing.T) {
	r := NewRouter(fullyWiredOptions(t))

	expected := []struct {
		method string
		path   string
	}{
		{"GET", "/healthz"},
		{"GET", "/readyz"},
		{"GET", "/version"},
		{"GET", "/metrics"},
		{"POST", "/api/v1/auth/login"},
		{"POST", "/api/v1/auth/refresh"},
		{"POST", "/api/v1/webhooks/irflow/incident_trigger"},
		{"POST", "/api/v1/auth/logout"},
		{"GET", "/api/v1/auth/me"},
		{"GET", "/api/v1/tracks"},
		{"GET", "/api/v1/tracks/t1"},
		{"GET", "/api/v1/tracks/t1/modules"},
		{"GET", "/api/v1/lessons/l1"},
		{"POST", "/api/v1/lessons/l1/complete"},
		{"GET", "/api/v1/quizzes/q1"},
		{"POST", "/api/v1/quizzes/q1/submit"},
		{"POST", "/api/v1/enrollments"},
		{"POST", "/api/v1/labs/l1/start"},
		{"POST", "/api/v1/labs/l1/stop"},
		{"GET", "/api/v1/labs/l1/status"},
		{"GET", "/api/v1/ws/labs/00000000-0000-0000-0000-000000000000/term"},
		{"GET", "/api/v1/users/u1/progress"},
		{"GET", "/api/v1/users/u1/certifications"},
		{"GET", "/api/v1/coverage/u1"},
		{"GET", "/api/v1/cyberpath/recommend"},
		{"POST", "/api/v1/certifications/issue"},
		{"GET", "/api/v1/me/certifications"},
		{"GET", "/api/v1/content/versions/00000000-0000-0000-0000-000000000000"},
		{"POST", "/api/v1/admin/content/reload"},
		{"DELETE", "/api/v1/admin/certifications/00000000-0000-0000-0000-000000000000/revoke"},
	}
	for _, e := range expected {
		req := httptest.NewRequest(e.method, e.path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("route %s %s not registered (status=%d)", e.method, e.path, rr.Code)
		}
	}
}

// TestRouterFullyWired_ConfigNil covers the opts.Config == nil branch of
// the devMode computation, still with a Verifier wired (so the
// short-circuit && actually gets exercised).
func TestRouterFullyWired_ConfigNil(t *testing.T) {
	opts := fullyWiredOptions(t)
	opts.Config = nil
	r := NewRouter(opts)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz: got status %d", rr.Code)
	}
}

// TestLoggerMiddleware_LogsRequest exercises loggerMiddleware's non-nil
// logger branch (the nil-logger branch is already covered implicitly by
// newTestRouter, which passes Logger: nil).
func TestLoggerMiddleware_LogsRequest(t *testing.T) {
	logger := zerolog.Nop()
	cfg := &config.Config{}
	cfg.Auth.DevMode = true
	r := NewRouter(Options{
		Config:  cfg,
		Logger:  &logger,
		Metrics: metrics.New(),
	})

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz: got status %d", rr.Code)
	}
}

// TestCorsMiddleware_PreflightOptions exercises the OPTIONS short-circuit
// branch of corsMiddleware (204, no downstream handler invoked) as well
// as the header-setting statements shared with normal requests.
func TestCorsMiddleware_PreflightOptions(t *testing.T) {
	r := newTestRouter(t)

	req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS /healthz: got status %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want *", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Errorf("Access-Control-Allow-Methods: got empty")
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Errorf("Access-Control-Allow-Headers: got empty")
	}
}

// TestMetricsMiddleware_NilRegistry exercises metricsMiddleware's nil-safety
// guard (Options.Metrics == nil skips the /metrics route and the counter
// increments become no-ops).
func TestMetricsMiddleware_NilRegistry(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.DevMode = true
	r := NewRouter(Options{Config: cfg})

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz: got status %d", rr.Code)
	}
}

// TestMetricsMiddleware_UnknownRoute exercises the pattern == "" fallback
// (r.URL.Path) branch in metricsMiddleware, reached when chi has no route
// pattern to report (i.e. the request didn't match any route).
func TestMetricsMiddleware_UnknownRoute(t *testing.T) {
	r := newTestRouter(t)

	req := httptest.NewRequest("GET", "/this-route-does-not-exist", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown route: got status %d, want 404", rr.Code)
	}
}
