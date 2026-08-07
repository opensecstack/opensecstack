// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/api/handlers"
	"github.com/opensecstack/securelab/internal/api/middleware"
	"github.com/opensecstack/securelab/internal/scenarios"
)

// NewRouter builds and returns the chi router with all SecureLab routes
// registered. startTime is passed through to the health handler so it can
// compute uptime. sinauthURL enables RS256 SSO token verification via the
// sinauth SDK; pass an empty string to disable the RS256 path.
func NewRouter(
	pool *pgxpool.Pool,
	scheduler *scenarios.Scheduler,
	jwtSecret string,
	sinauthURL string,
	startTime time.Time,
	log *zap.Logger,
) http.Handler {
	r := chi.NewRouter()

	// Global middleware.
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)

	// Unauthenticated routes.
	r.Get("/health", handlers.HealthHandler(pool, startTime))

	// Construct resource handlers.
	scenariosH := handlers.NewScenariosHandler(pool, scheduler, log)
	envsH := handlers.NewEnvironmentsHandler(pool, log)
	resultsH := handlers.NewResultsHandler(pool, log)
	coverageH := handlers.NewCoverageHandler(pool, log)

	// Authenticated API routes.
	r.Group(func(r chi.Router) {
		r.Use(middleware.Authenticate(jwtSecret, sinauthURL))

		// Scenarios — analyst+ read, operator+ write/run.
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/scenarios", scenariosH.ListScenarios)
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/scenarios/{id}", scenariosH.GetScenario)
		r.With(middleware.RequireRole("operator")).Post("/api/v1/scenarios", scenariosH.CreateScenario)
		r.With(middleware.RequireRole("operator")).Post("/api/v1/scenarios/{id}/run", scenariosH.RunScenario)

		// Runs — analyst+.
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/runs", resultsH.ListRuns)
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/runs/{id}", resultsH.GetRun)

		// Environments — analyst+ read, admin write.
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/environments", envsH.ListEnvironments)
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/environments/{id}", envsH.GetEnvironment)
		r.With(middleware.RequireRole("admin")).Post("/api/v1/environments", envsH.CreateEnvironment)
		r.With(middleware.RequireRole("admin")).Delete("/api/v1/environments/{id}", envsH.DeleteEnvironment)

		// MITRE ATT&CK coverage — analyst+.
		r.With(middleware.RequireRole("analyst")).Get("/api/v1/coverage", coverageH.GetCoverage)
	})

	return r
}
