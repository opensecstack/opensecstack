// Package api wires the HTTP server: chi router, middleware stack,
// handler registration. Follows the same pattern as IRFlow + CITADEL
// for consistency across the ecosystem.
package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/ratelimit"
)

// Options bundles everything the Server needs. Interfaces for service
// references let tests inject mocks.
type Options struct {
	Config             *config.Config
	Logger             *zerolog.Logger
	Pinger             handlers.Pinger
	Prompt             *handlers.PromptHandler
	Phishing           *handlers.PhishingHandler
	Identity           *handlers.IdentityHandler
	ThreatFeed         *handlers.ThreatFeedHandler
	Media              *handlers.MediaHandler
	ThreatflowReceiver *handlers.ThreatflowReceiver
	WebhookAdmin       *handlers.WebhookAdminHandler
	WebhookSubscribers *handlers.WebhookSubscribersHandler // VG-015
	AdminAtlas         *handlers.AdminAtlasHandler
	AdminPatterns      *handlers.AdminPatternsHandler
	AdminML            *handlers.AdminMLHandler
	Audit              *handlers.AuditHandler
	AuditSink          audit.Sink
	AuditMetrics       audit.MetricsHook
	Metrics            *metrics.Registry
	Authenticator      *auth.Verifier
	TokenRevoker       auth.Revoker
	Denylist           *handlers.DenylistAdminHandler
	RateLimitAdmin     *handlers.RateLimitAdminHandler
	RateLimiter        *ratelimit.Limiter
	RateLimitMetrics   ratelimit.Metrics
	Auth               *handlers.AuthHandler
	// Audio is the Phase 4.3 voice clone detection handler.
	// Nil disables the /api/v1/audio routes.
	Audio *handlers.AudioHandler
	// Video is the Phase 4.3 WebRTC deepfake detection handler.
	// Nil disables the /api/v1/video routes.
	Video *handlers.VideoStreamHandler
	// Meetings is the Phase 4.3 meeting-platform integration handler (Zoom /
	// Teams / WebEx). Nil disables the /api/v1/integrations/meetings/* routes.
	Meetings *handlers.MeetingsHandler
}

// Server wraps the chi router + lifecycle.
type Server struct {
	opts       Options
	httpServer *http.Server
}

// New builds a Server with the router + middleware configured.
func New(opts Options) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(clientIPMiddleware(opts.Config))
	r.Use(loggerMiddleware(opts.Logger))
	r.Use(metricsMiddleware(opts.Metrics))
	// Audit-aware recovery only when a sink is wired; otherwise fall
	// back to chi's stock Recoverer to avoid silently dropping panics.
	if opts.AuditSink != nil {
		r.Use(RecoveryMiddleware(opts.AuditSink, opts.Logger))
	} else {
		r.Use(middleware.Recoverer)
	}
	r.Use(middleware.Timeout(60 * time.Second))

	// ── Unauthenticated endpoints ────────────────────────────────
	// Split probes for Kubernetes: /livez gates pod kill, /readyz gates
	// LB traffic. /api/v1/health stays for backwards compat.
	r.Get("/livez", handlers.Live())
	r.Get("/readyz", handlers.ReadyHandler(opts.Pinger))
	r.Get("/api/v1/health", handlers.Health(opts.Pinger))

	// ── Authenticated API ────────────────────────────────────────
	r.Route("/api/v1", func(r chi.Router) {
		// Audit BEFORE auth so 401/403s on /api/v1/* are still recorded.
		if opts.AuditSink != nil {
			r.Use(audit.Middleware(opts.AuditSink, opts.Logger, opts.AuditMetrics))
		}
		if opts.Authenticator != nil {
			sinauthURL := opts.Config.Auth.SinauthURL
			if sinauthURL == "" {
				sinauthURL = "http://localhost:8100"
			}
			r.Use(auth.MiddlewareWithSinauth(
				opts.Authenticator,
				opts.Config.Auth.DevMode || opts.Config.Auth.Secret == "",
				sinauthURL,
				opts.Logger,
				opts.TokenRevoker,
			))
		}
		// Rate limit AFTER auth so we can key on the JWT subject; this
		// gives a fair quota per authenticated identity rather than per
		// shared NAT / proxy IP.
		if opts.RateLimiter != nil {
			r.Use(ratelimit.Middleware(opts.RateLimiter, opts.RateLimitMetrics, opts.Logger))
		}

		// /metrics moved under /api/v1 so the same JWT + read-role guard
		// that gates snapshot data also gates the Prometheus scrape
		// surface (snapshot exposes IOC counts, queue depths, etc — same
		// disclosure class). Scrapers must present a service-account JWT
		// with any known role.
		if opts.Metrics != nil {
			r.Get("/metrics", auth.RequireRead(promhttp.HandlerFor(
				opts.Metrics.Prometheus(),
				promhttp.HandlerOpts{Registry: opts.Metrics.Prometheus()},
			).ServeHTTP))
		}

		// /auth/whoami — claim introspection. RequireRead gates it on any
		// known role (admin/operator/verifier/viewer/service); the
		// no-claims branch in the handler is a defence-in-depth guard
		// for misconfiguration where the route ends up outside the auth
		// chain.
		if opts.Auth != nil {
			r.Get("/auth/whoami", auth.RequireRead(opts.Auth.Whoami))
		}

		// Module 3 — Prompt Injection
		if opts.Prompt != nil {
			r.Route("/prompt", func(r chi.Router) {
				r.Post("/scan", auth.RequireWrite(opts.Prompt.Scan))
			})
		}

		// Module 5 — Phishing Detection (rule-based v1)
		if opts.Phishing != nil {
			r.Route("/phishing", func(r chi.Router) {
				r.Post("/scan", auth.RequireWrite(opts.Phishing.Scan))
			})
		}

		// Module 6 — Identity Verification (rule-based v1)
		if opts.Identity != nil {
			r.Route("/identity", func(r chi.Router) {
				r.Post("/verify", auth.RequireWrite(opts.Identity.Verify))
			})
		}

		// Module 4 — AI Threat Feed
		if opts.ThreatFeed != nil {
			r.Route("/threatfeed", func(r chi.Router) {
				r.Get("/iocs", auth.RequireRead(opts.ThreatFeed.ListIOCs))
				// VG-006 — admin-only manual IOC insert.
				r.Post("/ioc", auth.RequireAdmin(opts.ThreatFeed.CreateIOC))
				r.Post("/atlas", auth.RequireRead(opts.ThreatFeed.MapATLAS))
				r.Get("/atlas/coverage", auth.RequireRead(opts.ThreatFeed.CoverageReport))
			})
		}

		// Module 1 — Media Authenticity (C2PA verification).
		// Handler returns 503 when verifier is nil (binary not configured).
		if opts.Media != nil {
			r.Route("/media", func(r chi.Router) {
				r.Post("/verify", auth.RequireWrite(opts.Media.Verify))
				r.Get("/scans/{scan_id}", auth.RequireRead(opts.Media.GetScan))
			})
		}
		// ThreatFlow webhook receiver — HMAC-verified inbound IOC events.
		if opts.ThreatflowReceiver != nil {
			r.Route("/webhooks", func(r chi.Router) {
				r.Post("/threatflow", opts.ThreatflowReceiver.Receive)
			})
		}
		r.Route("/admin", func(r chi.Router) {
			// Real impl when wired; fall back to 501 stubs so the route
			// table stays exhaustive in trimmed test setups.
			if opts.AdminPatterns != nil {
				r.Post("/patterns/reload", auth.RequireAdmin(opts.AdminPatterns.Reload))
			} else {
				r.Post("/patterns/reload", handlers.AdminPatternsReloadTODO)
			}
			if opts.AdminAtlas != nil {
				r.Post("/atlas/sync", auth.RequireAdmin(opts.AdminAtlas.Sync))
			} else {
				r.Post("/atlas/sync", handlers.AdminAtlasSyncTODO)
			}
			if opts.Audit != nil {
				r.Get("/audit", auth.RequireAdmin(opts.Audit.List))
			}
			if opts.Denylist != nil {
				r.Route("/denylist", func(r chi.Router) {
					r.Post("/", auth.RequireAdmin(opts.Denylist.Create))
					r.Get("/", auth.RequireAdmin(opts.Denylist.List))
					r.Delete("/{kind}/{value}", auth.RequireAdmin(opts.Denylist.Delete))
				})
			}
			if opts.AdminML != nil {
				r.Get("/ml/info", auth.RequireAdmin(opts.AdminML.Info))
			}
			if opts.RateLimitAdmin != nil {
				r.Route("/ratelimit/overrides", func(r chi.Router) {
					r.Post("/", auth.RequireAdmin(opts.RateLimitAdmin.Create))
					r.Get("/", auth.RequireAdmin(opts.RateLimitAdmin.List))
					r.Delete("/{kind}/{value}", auth.RequireAdmin(opts.RateLimitAdmin.Delete))
				})
			}
		})

		// VG-006 — ThreatFlow webhook subscriber management (admin).
		if opts.WebhookAdmin != nil {
			r.Route("/webhooks/subscribers", func(r chi.Router) {
				r.Post("/", auth.RequireAdmin(opts.WebhookAdmin.Create))
				r.Get("/", auth.RequireAdmin(opts.WebhookAdmin.List))
				r.Delete("/{id}", auth.RequireAdmin(opts.WebhookAdmin.Delete))
			})
		}

		// VG-015 — persistent outbound webhook subscribers with 3-slot
		// HMAC rotation. Distinct path (/webhook, singular) from the
		// legacy /webhooks plural so the two registries can coexist.
		if opts.WebhookSubscribers != nil {
			r.Route("/webhook/subscribers", func(r chi.Router) {
				r.Post("/", auth.RequireAdmin(opts.WebhookSubscribers.CreateV2))
				r.Get("/", auth.RequireAdmin(opts.WebhookSubscribers.ListV2))
				r.Delete("/{id}", auth.RequireAdmin(opts.WebhookSubscribers.DeleteV2))
				r.Post("/{id}/rotate", auth.RequireAdmin(opts.WebhookSubscribers.Rotate))
			})
		}

		// Phase 4.3 — Audio voice clone detection.
		// POST /api/v1/audio/score — score an audio fingerprint chunk.
		if opts.Audio != nil {
			r.Route("/audio", func(r chi.Router) {
				r.Post("/score", auth.RequireWrite(opts.Audio.Score))
			})
		}

		// Phase 4.3 — Video deepfake detection (WebRTC frame scoring).
		// POST  /api/v1/video/session               — create ephemeral session
		// WS    /api/v1/video/stream/{session_id}   — frame scoring stream
		if opts.Video != nil {
			r.Route("/video", func(r chi.Router) {
				r.Post("/session", auth.RequireWrite(opts.Video.CreateSession))
				r.Get("/stream/{session_id}", opts.Video.Stream)
			})
		}

		// Phase 4.3 — Meeting platform integrations (Zoom / Teams / WebEx).
		//
		// connect and status require JWT (RequireRead); webhook does NOT — the
		// platform sends unsigned requests validated by HMAC in the handler.
		if opts.Meetings != nil {
			r.Route("/integrations/meetings", func(r chi.Router) {
				r.Get("/connect/{platform}", auth.RequireRead(opts.Meetings.Connect))
				r.Get("/callback", auth.RequireRead(opts.Meetings.Callback))
				r.Get("/status", auth.RequireRead(opts.Meetings.Status))
				// Webhook is registered without RequireRead so the platform can
				// POST without a VertGuard JWT; HMAC validation happens inside
				// the handler.
				r.Post("/webhook/{platform}", opts.Meetings.Webhook)
			})
		}
	})

	return &Server{
		opts: opts,
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", opts.Config.Server.Port),
			Handler:      r,
			ReadTimeout:  opts.Config.Server.ReadTimeout,
			WriteTimeout: opts.Config.Server.WriteTimeout,
		},
	}
}

// Handler exposes the chi router for httptest-driven integration tests.
func (s *Server) Handler() http.Handler { return s.httpServer.Handler }

// Start begins listening. Blocks until Shutdown is called.
func (s *Server) Start() error {
	s.opts.Logger.Info().
		Int("port", s.opts.Config.Server.Port).
		Msg("vertguard HTTP server starting")
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ─── Middleware helpers ─────────────────────────────────────────────

// clientIPMiddleware replaces chi's deprecated middleware.RealIP, which
// unconditionally trusts True-Client-IP / X-Real-IP / X-Forwarded-For
// and is vulnerable to IP spoofing (GHSA-3fxj-6jh8-hvhx,
// GHSA-rjr7-jggh-pgcp, GHSA-9g5q-2w5x-hmxf) — any client could forge
// those headers to bypass per-IP rate limiting (internal/ratelimit) or
// forge the RemoteIP recorded in CITADEL audit events
// (internal/audit.ParseRemoteIP), both of which read r.RemoteAddr.
//
// Default (TrustedProxyHops == 0): never trust proxy headers, use the
// raw TCP peer address only — safe against spoofing, correct when this
// server is reachable directly.
//
// TrustedProxyHops > 0: the operator has confirmed exactly that many
// reverse proxies sit in front of this server and each unconditionally
// appends to X-Forwarded-For, so resolveClientIP walks exactly that
// many hops in from the right — an attacker-supplied XFF prefix can't
// reach a position the proxies overwrite.
//
// Either way the resolved IP is copied into r.RemoteAddr so existing
// downstream readers (ratelimit.keyFor, audit.ParseRemoteIP) keep
// working unchanged; only the trust model changes.
//
// chi v5.2.1's middleware package only ships the deprecated, header-
// trusting RealIP (see the GHSA advisories above) — it has no trusted-
// hop-count resolver, so this is implemented directly here instead of
// depending on a chi API that doesn't exist in the pinned version.
func clientIPMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	hops := 0
	if cfg != nil {
		hops = cfg.Server.TrustedProxyHops
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := resolveClientIP(r, hops); ip != "" {
				r.RemoteAddr = ip
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolveClientIP returns the client IP per the trust model documented on
// clientIPMiddleware. hops <= 0 always uses the raw TCP peer address.
func resolveClientIP(r *http.Request, hops int) string {
	if hops > 0 {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			idx := len(parts) - hops
			if idx < 0 {
				idx = 0
			}
			if ip := parts[idx]; ip != "" {
				return ip
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func loggerMiddleware(log *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			// chi RoutePattern gives the templated path so we don't
			// cardinal-explode on dynamic IDs.
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
