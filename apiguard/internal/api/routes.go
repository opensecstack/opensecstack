package api

import (
	"github.com/go-chi/chi/v5"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
)

// RegisterRoutes sets up all API routes on the given router.
func RegisterRoutes(r chi.Router, health *handlers.Health, scans *handlers.Scans, findings *handlers.Findings, cfg *config.Config) {
	r.Route("/api/v1", func(r chi.Router) {
		// Public endpoints.
		r.Get("/health", health.Health)
		r.Get("/version", health.Version)

		// Protected endpoints.
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(cfg.Auth.JWTSecret))

			// Scans.
			r.Post("/scans", scans.Create)
			r.Get("/scans", scans.List)
			r.Get("/scans/{id}", scans.Get)
			r.Get("/scans/{id}/findings", scans.Findings)
			r.Get("/scans/{id}/report", scans.Report)
			r.Delete("/scans/{id}", scans.Delete)

			// Findings.
			r.Get("/findings", findings.List)
			r.Get("/findings/{id}", findings.Get)
			r.Patch("/findings/{id}", findings.Update)
		})
	})
}
