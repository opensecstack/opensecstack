// Package api wires the CyberPath HTTP server: chi router, middleware,
// handler registration. Mirrors the VertGuard pattern.
package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/api/handlers"
	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/config"
	"github.com/opensecstack/cyberpath/internal/metrics"
)

// Options bundles everything NewRouter needs. Every handler-shaped
// field is optional — when nil the router falls back to the v0.0.1
// stubs so the dev server runs without every dependency wired.
type Options struct {
	Config   *config.Config
	Logger   *zerolog.Logger
	Pinger   handlers.Pinger
	Metrics  *metrics.Registry
	Verifier auth.Verifier

	// NIS2 reports NIS2 Compass connectivity from /readyz
	// (integrations.nis2compass). Nil omits the field entirely.
	NIS2 handlers.NIS2HealthChecker

	// Auth handlers (login/refresh/logout/me). Login + refresh sit
	// outside the JWT middleware; logout + me sit inside.
	Auth *handlers.AuthHandlers

	// IRFlowWebhook handles incoming HMAC-signed IRFlow webhooks.
	// Webhooks carry their own HMAC verification, so they are mounted
	// OUTSIDE the JWT middleware (HMAC IS their auth).
	IRFlowWebhook *handlers.IRFlowWebhookHandler

	// Coverage replaces the v0.0.1 NIS2 coverage/recommend stubs with
	// a NIS2-Compass-wired version. Falls back to stubs when nil.
	Coverage *handlers.CoverageHandler

	// ContentAdmin exposes /api/v1/admin/content/reload. Nil disables
	// the admin endpoint.
	ContentAdmin *handlers.ContentAdminHandler

	// DB-backed handlers (v1.0.0). Fall back to v0.0.1 stubs when nil.
	Tracks      *handlers.TracksHandler
	Lessons     *handlers.LessonsHandler
	Quizzes     *handlers.QuizHandler
	Labs        *handlers.LabsHandler
	Users       *handlers.UsersHandler
	Enrollments *handlers.EnrollmentHandler

	// Terminal serves the WebSocket lab terminal relay. Nil disables the route.
	Terminal *handlers.TerminalHandler

	// Certifications handles certification issuance, listing, and revocation.
	// Nil disables the certification endpoints.
	Certifications *handlers.CertificationsHandler

	// ContentVersions serves GET /content/versions/{id} for auditor reads.
	// Nil disables the route.
	ContentVersions *handlers.ContentVersionsHandler
}

// NewRouter builds a chi.Mux with the full middleware stack + routes.
func NewRouter(opts Options) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(loggerMiddleware(opts.Logger))
	r.Use(metricsMiddleware(opts.Metrics))
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware())
	r.Use(middleware.Timeout(60 * time.Second))

	// ── Unauthenticated probes ───────────────────────────────────
	r.Get("/healthz", handlers.Healthz())
	r.Get("/readyz", handlers.Readyz(opts.Pinger, opts.NIS2))
	r.Get("/version", handlers.Version())

	if opts.Metrics != nil {
		r.Handle("/metrics", promhttp.HandlerFor(
			opts.Metrics.Prometheus(),
			promhttp.HandlerOpts{Registry: opts.Metrics.Prometheus()},
		))
	}

	// ── Unauthenticated auth endpoints ───────────────────────────
	// Login + refresh do NOT require a bearer token (you cannot log
	// in without one in hand). They sit outside the protected group.
	if opts.Auth != nil {
		r.Post("/api/v1/auth/login", opts.Auth.Login())
		r.Post("/api/v1/auth/refresh", opts.Auth.Refresh())
	}

	// ── Incoming webhooks (HMAC-authenticated) ───────────────────
	// Webhooks have their own HMAC verification and MUST live outside
	// the JWT middleware — HMAC IS their auth.
	if opts.IRFlowWebhook != nil {
		opts.IRFlowWebhook.Register(r)
	}

	// ── API v1 (JWT-protected) ──────────────────────────────────
	//
	// Route → role policy (v1.0.0):
	//   /api/v1/admin/*       → admin only       (RequireRole(admin))
	//   /api/v1/...           → any authenticated user; per-resource
	//                           ownership (e.g. self-or-instructor for
	//                           /users/{id}/progress) is enforced inside
	//                           the handler — middleware cannot inspect
	//                           the path's {id} against claims.Sub
	//                           cleanly without coupling to chi params.
	r.Route("/api/v1", func(r chi.Router) {
		// JWT verification — skipped if no verifier wired.
		if opts.Verifier != nil {
			devMode := opts.Config != nil && (opts.Config.Auth.DevMode || opts.Config.Auth.Secret == "")
			r.Use(auth.Middleware(opts.Verifier, devMode, opts.Logger))
		}

		// Auth — protected endpoints (any authenticated user).
		if opts.Auth != nil {
			r.Post("/auth/logout", opts.Auth.Logout())
			r.Get("/auth/me", opts.Auth.Me())
		}

		// Tracks
		if opts.Tracks != nil {
			r.Get("/tracks", opts.Tracks.List)
			r.Get("/tracks/{id}", opts.Tracks.Get)
			r.Get("/tracks/{id}/modules", opts.Tracks.ListModules)
		} else {
			r.Get("/tracks", handlers.ListTracks())
			r.Get("/tracks/{id}", handlers.GetTrack())
			r.Get("/tracks/{id}/modules", handlers.ListTrackModules())
		}

		// Lessons
		if opts.Lessons != nil {
			r.Get("/lessons/{id}", opts.Lessons.Get)
			r.Post("/lessons/{id}/complete", opts.Lessons.Complete)
		} else {
			r.Get("/lessons/{id}", handlers.GetLesson())
			r.Post("/lessons/{id}/complete", handlers.CompleteLesson())
		}

		// Quizzes
		if opts.Quizzes != nil {
			r.Get("/quizzes/{id}", opts.Quizzes.Get)
			r.Post("/quizzes/{id}/submit", opts.Quizzes.Submit)
		} else {
			r.Post("/quizzes/{id}/submit", handlers.SubmitQuiz())
		}

		// Enrollments
		if opts.Enrollments != nil {
			r.Post("/enrollments", opts.Enrollments.Enroll)
		}

		// Labs
		if opts.Labs != nil {
			r.Post("/labs/{id}/start", opts.Labs.Start)
			r.Post("/labs/{id}/stop", opts.Labs.Stop)
			r.Get("/labs/{id}/status", opts.Labs.Status)
		} else {
			r.Post("/labs/{id}/start", handlers.StartLab())
			r.Post("/labs/{id}/stop", handlers.StopLab())
			r.Get("/labs/{id}/status", handlers.LabStatus())
		}

		// WebSocket terminal relay — only registered when Docker provisioning
		// is wired. The route lives inside /api/v1 so it inherits the JWT
		// middleware; the WebSocket client must send the token as a query
		// parameter or sub-protocol header before upgrading.
		if opts.Terminal != nil {
			r.Get("/ws/labs/{sessionID}/term", opts.Terminal.ServeHTTP)
		}

		// Users — handler enforces self-or-instructor ownership.
		if opts.Users != nil {
			r.Get("/users/{id}/progress", opts.Users.Progress)
			r.Get("/users/{id}/certifications", opts.Users.Certifications)
		} else {
			r.Get("/users/{id}/progress", handlers.UserProgress())
			r.Get("/users/{id}/certifications", handlers.UserCertifications())
		}

		// NIS2 coverage / recommendations — wired version when
		// Options.Coverage is supplied, stub otherwise.
		if opts.Coverage != nil {
			r.Get("/coverage/{user_id}", opts.Coverage.Coverage())
			r.Get("/cyberpath/recommend", opts.Coverage.Recommend())
		} else {
			r.Get("/coverage/{user_id}", handlers.Coverage())
			r.Get("/cyberpath/recommend", handlers.Recommend())
		}

		// Certifications — issuance + self-listing (any authenticated user).
		// Revocation sits in the admin sub-router below.
		if opts.Certifications != nil {
			r.Post("/certifications/issue", opts.Certifications.Issue)
			r.Get("/me/certifications", opts.Certifications.ListMine)
		}

		// Content versions — auditor read by UUID primary key.
		if opts.ContentVersions != nil {
			r.Get("/content/versions/{id}", opts.ContentVersions.Get)
		}

		// Admin sub-router — RequireRole(admin) gates everything below.
		if opts.ContentAdmin != nil || opts.Certifications != nil {
			r.Route("/admin", func(r chi.Router) {
				if opts.Verifier != nil {
					r.Use(auth.RequireRole(auth.RoleAdmin))
				}
				if opts.ContentAdmin != nil {
					r.Post("/content/reload", opts.ContentAdmin.Reload())
				}
				if opts.Certifications != nil {
					r.Delete("/certifications/{id}/revoke", opts.Certifications.Revoke)
				}
			})
		}
	})

	return r
}

// ── Middleware helpers ─────────────────────────────────────────────

func loggerMiddleware(log *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log == nil {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(rw, r)
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", rw.Status()).
				Int("bytes", rw.BytesWritten()).
				Dur("duration", time.Since(start)).
				Str("request_id", middleware.GetReqID(r.Context())).
				Msg("http request")
		})
	}
}

func metricsMiddleware(reg *metrics.Registry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reg == nil {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(rw, r)
			pattern := chi.RouteContext(r.Context()).RoutePattern()
			if pattern == "" {
				pattern = r.URL.Path
			}
			reg.HTTPRequestsTotal.WithLabelValues(
				r.Method, pattern, fmt.Sprintf("%d", rw.Status()),
			).Inc()
			reg.HTTPRequestDuration.WithLabelValues(r.Method, pattern).
				Observe(time.Since(start).Seconds())
		})
	}
}

// corsMiddleware is a permissive CORS shim for v0.0.1; v1.0.0 will read
// allowed origins from config.
func corsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-Id")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

