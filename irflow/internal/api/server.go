package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"go.uber.org/zap"
)

// Server is the main HTTP server for the IRFlow API.
type Server struct {
	router    chi.Router
	logger    *zap.Logger
	incidents *incident.Service
}

// NewServer creates a new Server with middleware and routes configured.
func NewServer(logger *zap.Logger, incidents *incident.Service) *Server {
	s := &Server{
		router:    chi.NewRouter(),
		logger:    logger,
		incidents: incidents,
	}
	s.setupMiddleware()
	s.setupRoutes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) setupMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.Compress(5))
}

func (s *Server) setupRoutes() {
	s.router.Get("/health", s.handleHealth)
	s.router.Get("/health/detail", s.handleHealthDetail)

	s.router.Route("/api/v1", func(r chi.Router) {
		// Incident CRUD and sub-resources.
		r.Route("/incidents", func(r chi.Router) {
			r.Get("/", s.handleListIncidents)
			r.Post("/", s.handleCreateIncident)
			r.Route("/{incidentID}", func(r chi.Router) {
				r.Get("/", s.handleGetIncident)
				r.Patch("/", s.handlePatchIncident)
				r.Delete("/", s.handleDeleteIncident)
				r.Post("/actions", s.handleSubmitAction)
				r.Get("/actions", s.handleListActions)
				r.Get("/timeline", s.handleGetTimeline)
				r.Post("/iocs", s.handleAddIOC)
				r.Get("/iocs", s.handleListIOCs)
			})
		})

		// Playbook management (not yet implemented).
		r.Route("/playbooks", func(r chi.Router) {
			r.Get("/", s.handleListPlaybooks)
			r.Post("/", s.handleCreatePlaybook)
			r.Route("/{playbookID}", func(r chi.Router) {
				r.Get("/", s.handleGetPlaybook)
				r.Patch("/", s.handlePatchPlaybook)
				r.Delete("/", s.handleDeletePlaybook)
				r.Post("/execute", s.handleExecutePlaybook)
			})
		})

		// Inbound webhooks from other opensecstack services.
		r.Post("/webhooks/apiguard", s.handleAPIGuardWebhook)
		r.Post("/webhooks/citadel", s.handleCITADELWebhook)
		r.Post("/webhooks/threatflow", s.handleThreatFlowWebhook)

		// Dashboard statistics.
		r.Get("/stats", s.handleGetStats)
	})
}
