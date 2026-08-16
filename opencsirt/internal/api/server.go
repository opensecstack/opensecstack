// Package api wires the chi router and middleware stack.
package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/opensecstack/opencsirt/internal/api/handlers"
	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/metrics"
)

type Deps struct {
	Auth           *auth.Authenticator
	AuthHandler    *handlers.Auth
	Health         *handlers.Health
	Snapshot       *handlers.Snapshot
	Constituency   *handlers.Constituency
	Incident       *handlers.Incident
	Advisory       *handlers.Advisory
	Peers          *handlers.Peers
	IRFlowWebhook  http.Handler
	TaranisWebhook http.Handler
}

func Router(d Deps) http.Handler {
	r := chi.NewRouter()
	// Recoverer must be outermost so it catches panics from all middleware
	// beneath it, including Timeout (which can panic on context cancellation).
	r.Use(chimw.Recoverer)
	// chimw.RealIP is deliberately NOT used: it blindly trusts the leftmost
	// X-Forwarded-For / X-Real-IP / True-Client-IP header from any client,
	// letting a spoofed header override r.RemoteAddr with no trusted-proxy
	// allowlist to validate against (GHSA-3fxj-6jh8-hvhx). Nothing in this
	// service currently keys a security decision off the client IP, so the
	// safer default is the raw TCP peer address chi/net/http already set.
	r.Use(chimw.RequestID)
	r.Use(chimw.Timeout(30 * time.Second))

	// Public endpoints.
	r.Get("/api/v1/health", d.Health.Get)
	r.Post("/api/v1/auth/login", d.AuthHandler.Login)
	if d.IRFlowWebhook != nil {
		r.Method(http.MethodPost, "/api/v1/integrations/irflow/incident", d.IRFlowWebhook)
	}
	if d.TaranisWebhook != nil {
		r.Method(http.MethodPost, "/api/v1/integrations/taranis/osint", d.TaranisWebhook)
	}

	// Authenticated endpoints.
	r.Group(func(r chi.Router) {
		r.Use(d.Auth.Middleware)

		// Metrics — JWT-gated under analyst+ role (no public scrape).
		r.With(auth.RequireRole(auth.RoleAnalyst)).Handle("/api/v1/metrics", metrics.Handler())
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/metrics/snapshot", d.Snapshot.Get)

		// Constituencies.
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/constituencies", d.Constituency.List)
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/constituencies/{id}", d.Constituency.Get)
		r.With(auth.RequireRole(auth.RoleOperator)).Post("/api/v1/constituencies", d.Constituency.Create)
		r.With(auth.RequireRole(auth.RoleOperator)).Put("/api/v1/constituencies/{id}", d.Constituency.Update)

		// Incidents.
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/incidents", d.Incident.List)
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/incidents/{id}", d.Incident.Get)
		r.With(auth.RequireRole(auth.RoleOperator)).Post("/api/v1/incidents", d.Incident.Create)
		r.With(auth.RequireRole(auth.RoleOperator)).Post("/api/v1/incidents/{id}/escalate", d.Incident.Escalate)
		r.With(auth.RequireRole(auth.RoleOperator)).Post("/api/v1/incidents/{id}/close", d.Incident.Close)

		// Advisories.
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/advisories", d.Advisory.List)
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/advisories/{id}", d.Advisory.Get)
		r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/advisories/{id}/csaf", d.Advisory.GetCSAF)
		r.With(auth.RequireRole(auth.RoleOperator)).Post("/api/v1/advisories", d.Advisory.Create)
		r.With(auth.RequireRole(auth.RoleCSIRTLead)).Post("/api/v1/advisories/{id}/publish", d.Advisory.Publish)
		r.With(auth.RequireRole(auth.RoleCSIRTLead)).Post("/api/v1/advisories/{id}/withdraw", d.Advisory.Withdraw)

		// Peers.
		if d.Peers != nil {
			r.With(auth.RequireRole(auth.RoleAnalyst)).Get("/api/v1/peers", d.Peers.List)
			r.With(auth.RequireRole(auth.RoleOperator)).Post("/api/v1/peers/{id}/handshake", d.Peers.Handshake)
		}
	})

	return r
}
