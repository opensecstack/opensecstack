package api

import (
	"net"

	"github.com/go-chi/chi/v5"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
)

// RegisterRoutes sets up all API routes on the given router.
// authLimiter, scanLimiter, reportLimiter, refreshLimiter, and apiKeyLimiter
// must be created by the caller (stored on the Server) so their Stop() methods
// can be called on shutdown. trustedProxies is forwarded to JWTAuth so auth
// failures log the real client IP.
func RegisterRoutes(
	r chi.Router,
	health *handlers.Health,
	auth *handlers.Auth,
	scans *handlers.Scans,
	findings *handlers.Findings,
	specs *handlers.Specs,
	audit *handlers.Audit,
	apiKeys *handlers.APIKeys,
	metrics *middleware.MetricsCollector,
	cfg *config.Config,
	authLimiter *middleware.RateLimiter,
	scanLimiter *middleware.RateLimiter,
	reportLimiter *middleware.RateLimiter,
	refreshLimiter *middleware.RateLimiter,
	apiKeyLimiter *middleware.RateLimiter,
	trustedProxies []*net.IPNet,
) {

	r.Route("/api/v1", func(r chi.Router) {
		// ── Public endpoints (no JWT required) ──────────────────────────────
		r.Get("/health", health.Health)
		r.Get("/version", health.Version)

		// Auth: obtain a JWT from a pre-shared API key.
		// Apply a strict per-IP rate limiter to prevent brute-force attacks.
		r.Group(func(r chi.Router) {
			r.Use(authLimiter.Middleware)
			r.Get("/auth/token", auth.Ping)            // GET  → instructions / meta
			r.Post("/auth/token", auth.Token)          // POST → exchange api_key → JWT
			r.Post("/auth/refresh", auth.RefreshToken) // POST → exchange refresh_token → new tokens
		})

		// Refresh token revocation and listing — dedicated rate limiter (20 req/min).
		r.Group(func(r chi.Router) {
			r.Use(refreshLimiter.Middleware)
			r.Get("/auth/refresh", auth.ListRefreshTokens)     // GET    → list recently revoked tokens
			r.Delete("/auth/refresh", auth.RevokeRefreshToken) // DELETE → revoke a refresh token
		})

		r.Get("/openapi.json", handlers.OpenAPI)
		r.Get("/metrics", metrics.Handler())

		// ── Protected endpoints (Bearer JWT required) ────────────────────────
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuthWithRotation(cfg.Auth.JWTSecret, cfg.Auth.PreviousJWTSecret, trustedProxies))

			// Scans — scan creation is expensive; apply a dedicated rate limiter.
			r.With(scanLimiter.Middleware).Post("/scans", scans.Create)
			r.Get("/scans", scans.List)
			r.Get("/scans/{id}", scans.Get)
			r.Get("/scans/{id}/findings", scans.Findings)
			r.With(reportLimiter.Middleware).Get("/scans/{id}/report", scans.Report)
			r.Delete("/scans/{id}", scans.Delete)

			// Findings.
			r.Get("/findings", findings.List)
			r.Get("/findings/{id}", findings.Get)
			r.Patch("/findings/{id}", findings.Update)

			// Specs: upload an OpenAPI spec file to the server.
			r.Post("/specs/upload", specs.Upload)

			// Audit log.
			r.Get("/audit", audit.List)

			// API key management.
			r.Route("/api-keys", func(r chi.Router) {
				r.Get("/", apiKeys.List)
				r.With(apiKeyLimiter.Middleware).Post("/", apiKeys.Create) // rate-limited: 5 req/min
				r.Delete("/{id}", apiKeys.Revoke)
			})
		})
	})
}
