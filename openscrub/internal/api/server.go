// Package api wires the HTTP server: chi router, auth middleware,
// route registration. Constructed by cmd/openscrub/main.go.
package api

import (
	"context"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/metrics"
)

// Deps bundles the handler dependencies.
type Deps struct {
	Health      *handlers.Health
	Rules       *handlers.Rules
	Mitigations *handlers.Mitigations
	Snapshot    *handlers.Snapshot
	Auth        *handlers.Auth
	Verifier    auth.Verifier
	DevMode     bool
	Logger      zerolog.Logger
}

// NewRouter returns a chi router with all routes registered.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	// middleware.RealIP is deliberately NOT used: it blindly trusts the
	// leftmost X-Forwarded-For / X-Real-IP / True-Client-IP header from any
	// client, letting a spoofed header override r.RemoteAddr with no
	// trusted-proxy allowlist to validate against (GHSA-3fxj-6jh8-hvhx).
	// Nothing in this service currently keys a security decision off the
	// client IP, so the safer default is the raw TCP peer address chi/
	// net/http already set.
	r.Use(middleware.RequestID)
	r.Use(quietRecoverer(d.Logger))
	r.Use(middleware.Timeout(30 * time.Second))

	// Health is unauthenticated. /metrics is auth-gated below — the
	// Prometheus surface exposes counters that leak operational state
	// (rule counts, IOC pull cadence, CITADEL queue depth) and must
	// not be open to the internet.
	r.Get("/api/v1/health", d.Health.Get)
	// /readyz is the Kubernetes readinessProbe target — strict (DB +
	// dataplane); /health stays liveness-only so transient DB failovers
	// don't trigger pod restarts.
	r.Get("/api/v1/readyz", d.Health.Ready)

	// /api/v1/auth/login is unauthenticated by definition. The handler
	// itself returns 503 when no credentials are seeded so the dashboard
	// gets a meaningful error instead of a 404.
	if d.Auth != nil {
		r.Post("/api/v1/auth/login", d.Auth.Login)
	}

	metricsHandler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}).ServeHTTP

	// Authenticated API.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.Middleware(d.Verifier, d.DevMode, &d.Logger))

		// /auth/whoami — dashboard probe that turns "is my stored JWT
		// still valid against the current server secrets?" into a real
		// network round-trip (the client-side jwt.ts only inspects
		// exp). Open to any authenticated role.
		if d.Auth != nil {
			r.With(auth.RequireRole(
				auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor,
				auth.RoleAnalyst, auth.RoleReadOnly,
			)).Get("/auth/whoami", d.Auth.Whoami)
		}

		r.With(auth.RequireRole(
			auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor,
			auth.RoleAnalyst, auth.RoleReadOnly,
		)).Get("/metrics", metricsHandler)

		// /metrics/snapshot — JSON-shaped point-in-time view for the
		// dashboard. Read-only; analyst+ role.
		if d.Snapshot != nil {
			r.With(auth.RequireRole(
				auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor,
				auth.RoleAnalyst, auth.RoleReadOnly,
			)).Get("/metrics/snapshot", d.Snapshot.Get)
		}

		if d.Mitigations != nil {
			r.With(auth.RequireRole(
				auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor,
				auth.RoleAnalyst, auth.RoleReadOnly,
			)).Get("/mitigations", d.Mitigations.List)
		}

		r.Route("/rules", func(r chi.Router) {
			// Read: any authenticated role (RequireRole degrades to dev-bypass when no claims).
			r.With(auth.RequireRole(
				auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor,
				auth.RoleAnalyst, auth.RoleReadOnly,
			)).Get("/", d.Rules.List)
			r.With(auth.RequireRole(
				auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor,
				auth.RoleAnalyst, auth.RoleReadOnly,
			)).Get("/{id}", d.Rules.Get)
			// Mutate: admin or operator only.
			r.With(auth.RequireRole(auth.RoleAdmin, auth.RoleOperator)).
				Post("/", d.Rules.Create)
			r.With(auth.RequireRole(auth.RoleAdmin, auth.RoleOperator)).
				Delete("/{id}", d.Rules.Delete)
		})
	})

	return r
}

// quietRecoverer replaces middleware.Recoverer's default behaviour
// (debug.PrintStack to stderr + a stack-leaking HTML body in non-prod
// modes) with a structured zerolog entry and a vanilla 500 response.
// We never want stack frames in the response body — they leak file
// paths, function names, and (when middleware.Recoverer is configured
// with the chi env vars) sometimes literal source snippets.
func quietRecoverer(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rv := recover(); rv != nil && rv != http.ErrAbortHandler {
					log.Error().
						Interface("panic", rv).
						Bytes("stack", debug.Stack()).
						Str("path", r.URL.Path).
						Msg("panic in handler")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"internal server error"}}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Server wraps an *http.Server with sensible timeouts and graceful shutdown.
type Server struct {
	srv *http.Server
	log zerolog.Logger
}

// NewServer builds a Server bound to addr.
func NewServer(addr string, handler http.Handler, log zerolog.Logger) *Server {
	return &Server{
		srv: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
		},
		log: log,
	}
}

// ListenAndServe runs the server until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info().Str("addr", s.srv.Addr).Msg("openscrub api listening")
		errCh <- s.srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
