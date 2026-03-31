package api

import (
	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/threatflow/internal/api/handlers"
	"github.com/opensecstack/threatflow/internal/config"
)

// Server is the ThreatFlow HTTP API server.
type Server struct {
	router chi.Router
	logger zerolog.Logger
	config *config.Config
}

// NewServer creates a new Server with routes registered.
func NewServer(cfg *config.Config) *Server {
	r := chi.NewRouter()
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)

	s := &Server{
		router: r,
		logger: log.With().Str("component", "api").Logger(),
		config: cfg,
	}
	s.registerRoutes()
	return s
}

// Router returns the chi.Router for use by http.Server.
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) registerRoutes() {
	health := handlers.NewHealth(s.logger)
	ioc := handlers.NewIOC(s.logger)

	s.router.Route("/api/v1", func(r chi.Router) {
		// Public
		r.Get("/health", health.Health)
		r.Get("/version", health.Version)

		// IOC feeds (placeholder — will require JWT in production)
		r.Get("/iocs", ioc.List)
		r.Post("/iocs", ioc.Ingest)
		r.Get("/iocs/{id}", ioc.Get)

		// STIX bundles (placeholder)
		r.Get("/stix/bundles", ioc.ListBundles)
		r.Post("/stix/bundles", ioc.IngestBundle)
	})
}
