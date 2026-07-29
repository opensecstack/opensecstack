package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/auth"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

// Pinger verifies backing-store connectivity for health checks.
type Pinger interface {
	Ping(ctx context.Context) error
}

// WebhookSecrets carries per-source HMAC signing keys for inbound webhooks.
// When a source's secret is empty, that webhook endpoint returns 503 so a
// misconfigured IRFlow can never accept unauthenticated events.
type WebhookSecrets struct {
	APIGuard    string
	CITADEL     string
	ThreatFlow  string
	CyberPath   string
	MaxBodySize int64
	ClockSkew   time.Duration
}

// Options bundles every dependency Server needs. Using a struct here means
// future phases can add fields without breaking existing callers.
type Options struct {
	Logger    *zap.Logger
	Incidents *incident.Service
	Playbooks *playbook.Service
	Pinger    Pinger
	Webhooks  WebhookSecrets
	Auth      auth.Config
	Metrics   *metrics.Metrics
}

// Server is the main HTTP server for the IRFlow API.
type Server struct {
	router    chi.Router
	logger    *zap.Logger
	incidents *incident.Service
	playbooks *playbook.Service
	pinger    Pinger
	webhooks  WebhookSecrets
	auth      auth.Config
	metrics   *metrics.Metrics
}

// NewServer constructs a Server from an Options struct. All fields are
// optional — the server routes that require a given dependency will return
// 503 when that dependency is nil.
func NewServer(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if opts.Webhooks.MaxBodySize == 0 {
		opts.Webhooks.MaxBodySize = 1 << 20
	}
	if opts.Webhooks.ClockSkew == 0 {
		opts.Webhooks.ClockSkew = 5 * time.Minute
	}
	opts.Auth.Logger = opts.Logger
	// Zero-value auth is treated as dev mode with a warning. Production
	// deployments must either set a non-empty Secret (which enables JWT
	// enforcement) or explicitly set Disabled=true to acknowledge the risk.
	if opts.Auth.Secret == "" && !opts.Auth.Disabled {
		opts.Auth.Disabled = true
		opts.Logger.Warn("auth: middleware auto-disabled — no signing secret configured; all API routes are open")
	}
	s := &Server{
		router:    chi.NewRouter(),
		logger:    opts.Logger,
		incidents: opts.Incidents,
		playbooks: opts.Playbooks,
		pinger:    opts.Pinger,
		webhooks:  opts.Webhooks,
		auth:      opts.Auth,
		metrics:   opts.Metrics,
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
	if s.metrics != nil {
		s.router.Use(s.metrics.HTTPMiddleware())
		s.router.Use(s.metrics.InFlightMiddleware())
	}
	// AuditLog wraps the request BEFORE auth runs so we capture rejections too.
	s.router.Use(auth.AuditLog(s.logger))
}

func (s *Server) setupRoutes() {
	// ---------- Public routes ----------
	s.router.Get("/health", s.handleHealth)
	s.router.Get("/health/detail", s.handleHealthDetail)
	if s.metrics != nil {
		s.router.Method(http.MethodGet, "/metrics", s.metrics.Handler())
	}

	// Webhooks authenticate themselves via HMAC signature (see webhook package)
	// rather than JWT, so they live outside the JWT-protected group.
	s.router.Route("/api/v1/webhooks", func(r chi.Router) {
		r.Post("/apiguard", s.handleAPIGuardWebhook)
		r.Post("/citadel", s.handleCITADELWebhook)
		r.Post("/threatflow", s.handleThreatFlowWebhook)
		r.Post("/cyberpath/remediation", s.handleCyberPathWebhook)
	})

	// ---------- JWT-protected routes ----------
	s.router.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.Middleware(s.auth))

		// Incident CRUD and sub-resources.
		r.Route("/incidents", func(r chi.Router) {
			r.Get("/", s.handleListIncidents)
			r.With(auth.RequireWrite()).Post("/", s.handleCreateIncident)
			r.Route("/{incidentID}", func(r chi.Router) {
				r.Get("/", s.handleGetIncident)
				r.With(auth.RequireWrite()).Patch("/", s.handlePatchIncident)
				r.With(auth.RequireDelete()).Delete("/", s.handleDeleteIncident)
				r.Route("/actions", func(r chi.Router) {
					r.Get("/", s.handleListActions)
					r.Get("/pending", s.handleListPendingActions)
					r.With(auth.RequireWrite()).Post("/", s.handleProposeAction)
					r.Route("/{actionID}", func(r chi.Router) {
						r.With(auth.RequireApprove()).Post("/approve", s.handleApproveAction)
						r.With(auth.RequireApprove()).Post("/reject", s.handleRejectAction)
					})
				})
				r.Get("/timeline", s.handleGetTimeline)
				r.With(auth.RequireWrite()).Post("/iocs", s.handleAddIOC)
				r.Get("/iocs", s.handleListIOCs)
			})
		})

		// Playbook management.
		r.Route("/playbooks", func(r chi.Router) {
			r.Get("/", s.handleListPlaybooks)
			r.With(auth.RequireWrite()).Post("/", s.handleCreatePlaybook)
			r.Route("/{playbookID}", func(r chi.Router) {
				r.Get("/", s.handleGetPlaybook)
				r.With(auth.RequireWrite()).Patch("/", s.handlePatchPlaybook)
				r.With(auth.RequireDelete()).Delete("/", s.handleDeletePlaybook)
				r.With(auth.RequireWrite()).Post("/execute", s.handleExecutePlaybook)
				r.Get("/executions", s.handleListExecutions)
			})
		})

		// Execution inspection.
		r.Get("/executions/{executionID}", s.handleGetExecution)

		// Dashboard statistics.
		r.Get("/stats", s.handleGetStats)
	})
}
