package api

import (
	"net"

	"github.com/go-chi/chi/v5"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/sdk/go/sinauth"
)

// RegisterRoutes sets up all API routes on the given router.
// authLimiter, scanLimiter, reportLimiter, refreshLimiter, and apiKeyLimiter
// must be created by the caller (stored on the Server) so their Stop() methods
// can be called on shutdown. trustedProxies is forwarded to JWTAuth so auth
// failures log the real client IP.
//
// denylist is the access-token denylist shared between the Logout handler and
// the JWT validation middleware. Pass nil to disable access-token logout
// (refresh-token revocation is always available regardless).
func RegisterRoutes(
	r chi.Router,
	health *handlers.Health,
	auth *handlers.Auth,
	scans *handlers.Scans,
	findings *handlers.Findings,
	specs *handlers.Specs,
	audit *handlers.Audit,
	apiKeys *handlers.APIKeys,
	inventory *handlers.Inventory,
	webhooks *handlers.Webhooks,
	metrics *middleware.MetricsCollector,
	cfg *config.Config,
	authLimiter    middleware.Limiter,
	scanLimiter    middleware.Limiter,
	reportLimiter  middleware.Limiter,
	refreshLimiter middleware.Limiter,
	apiKeyLimiter  middleware.Limiter,
	secrets        *middleware.SecretProvider,
	denylist       *middleware.TokenDenylist,
	sinauthClient  *sinauth.Client,
	trustedProxies []*net.IPNet,
) {
	// Dedicated rate limiter for the /metrics endpoint (30 req/min per IP).
	// Created inline because its lifecycle is tied to the router, not the server.
	metricsLimiter := middleware.NewRateLimiter(30)

	r.Route("/api/v1", func(r chi.Router) {
		// M3: enforce application/json Content-Type on all mutation requests
		// within the API router. Health, metrics, and GET endpoints are unaffected.
		r.Use(middleware.RequireJSONContentType)

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
		r.With(metricsLimiter.Middleware).Get("/metrics", metrics.Handler())
		r.With(metricsLimiter.Middleware).Get("/metrics/prometheus", middleware.PrometheusHandler())

		// ── Inbound webhooks (HMAC-authenticated, no JWT) ────────────────────
		r.Post("/webhooks/citadel", webhooks.HandleCITADEL)

		// ── Protected endpoints (Bearer JWT required) ────────────────────────
		r.Group(func(r chi.Router) {
			// Use the sinauth+denylist-aware variant: RS256 tokens from sinauth
			// are verified first; HS256 tokens fall back to the HMAC provider.
			r.Use(middleware.JWTAuthWithProviderDenylistAndSinauth(secrets, denylist, sinauthClient, trustedProxies))

			// Access-token logout — must be inside the JWT-protected group so
			// only a valid (not-yet-denied) token can be submitted for denylist
			// entry. Rate-limited by the authLimiter to match token issuance.
			r.With(authLimiter.Middleware).Post("/auth/logout", auth.Logout)

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

			// API Inventory.
			r.Get("/inventory", inventory.List)
			r.Get("/inventory/{id}/history", inventory.GetHistory)

			// API key management.
			r.Route("/api-keys", func(r chi.Router) {
				r.Get("/", apiKeys.List)
				r.With(apiKeyLimiter.Middleware).Post("/", apiKeys.Create) // rate-limited: 5 req/min
				r.Delete("/{id}", apiKeys.Revoke)
			})

			// JWT secret rotation (protected — any authenticated user with admin intent).
			r.Post("/admin/auth/rotate", auth.RotateSecret)
		})
	})
}
