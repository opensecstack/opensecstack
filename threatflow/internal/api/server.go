package api

import (
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/threatflow/internal/api/handlers"
	"github.com/opensecstack/threatflow/internal/api/middleware"
	"github.com/opensecstack/threatflow/internal/auth"
	"github.com/opensecstack/threatflow/internal/cache"
	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/config"
	"github.com/opensecstack/threatflow/internal/correlate"
	"github.com/opensecstack/threatflow/internal/csaf"
	"github.com/opensecstack/threatflow/internal/db"
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/stix"
	"github.com/opensecstack/threatflow/internal/webhook"
)

// Server is the ThreatFlow HTTP API server.
type Server struct {
	router     chi.Router
	logger     zerolog.Logger
	config     *config.Config
	db         *db.DB
	Importer   *stix.Importer
	Feeds      *store.FeedStore
	Citadel    *citadel.Client
	Dispatcher *webhook.Dispatcher
	Auth       *auth.Service
	Cache      *cache.Cache
}

// NewServer creates a new Server with routes registered.
func NewServer(cfg *config.Config, database *db.DB, citadelC *citadel.Client, authSvc *auth.Service, c *cache.Cache) *Server {
	r := chi.NewRouter()
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)

	s := &Server{
		router:  r,
		logger:  log.With().Str("component", "api").Logger(),
		config:  cfg,
		db:      database,
		Citadel: citadelC,
		Auth:    authSvc,
		Cache:   c,
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

	var (
		iocStore      *store.IOCStore
		stixStore     *store.StixStore
		feedStore     *store.FeedStore
		ttpStore      *store.TTPStore
		corrStore     *store.CorrelationStore
		webhookStore  *store.WebhookStore
		sightingStore *store.SightingStore
		apiKeyStore   *store.APIKeyStore
		advisoryStore *store.AdvisoryStore
		importer      *stix.Importer
		csafImporter  *csaf.Importer
		engine        *correlate.Engine
		dispatcher    *webhook.Dispatcher
	)
	if s.db != nil {
		iocStore = store.NewIOCStore(s.db.Pool)
		stixStore = store.NewStixStore(s.db.Pool)
		feedStore = store.NewFeedStore(s.db.Pool)
		ttpStore = store.NewTTPStore(s.db.Pool)
		corrStore = store.NewCorrelationStore(s.db.Pool)
		webhookStore = store.NewWebhookStore(s.db.Pool)
		sightingStore = store.NewSightingStore(s.db.Pool)
		apiKeyStore = store.NewAPIKeyStore(s.db.Pool)
		advisoryStore = store.NewAdvisoryStore(s.db.Pool)
		engine = correlate.New(s.db.Pool, corrStore, s.logger)
		dispatcher = webhook.NewDispatcher(webhookStore, s.logger)
		importer = stix.NewImporter(stixStore, iocStore, ttpStore, engine, s.logger)
		csafImporter = csaf.NewImporter(advisoryStore, stixStore, s.logger)
	}
	s.Importer = importer
	s.Feeds = feedStore
	s.Dispatcher = dispatcher

	ioc := handlers.NewIOC(s.logger, iocStore, s.Citadel, engine, dispatcher, s.Cache)
	stixH := handlers.NewSTIX(s.logger, stixStore, importer, s.Citadel, dispatcher)
	feedH := handlers.NewFeed(s.logger, feedStore, s.Citadel)
	techH := handlers.NewTechnique(s.logger, ttpStore)
	corrH := handlers.NewCorrelation(s.logger, corrStore)
	webhookH := handlers.NewWebhook(s.logger, webhookStore)
	sightH := handlers.NewSighting(s.logger, sightingStore, iocStore, dispatcher, s.Cache)
	authH := handlers.NewAuth(s.logger, s.Auth, apiKeyStore)
	advisoryH := handlers.NewAdvisory(s.logger, advisoryStore, csafImporter, s.Citadel, dispatcher)

	// Rate-limit middleware — keeps a shared instance so it tracks the
	// same IP buckets across all routes.
	rps := s.config.Rate.RequestsPerSec
	if rps <= 0 {
		rps = 50
	}
	burst := s.config.Rate.Burst
	if burst <= 0 {
		burst = 100
	}
	rateLimiter := middleware.NewRateLimiter(rps, burst)

	s.router.Route("/api/v1", func(r chi.Router) {
		// Public — health/version have no auth, no rate limit (keeps liveness probes simple).
		r.Get("/health", health.Health)
		r.Get("/version", health.Version)

		// Token exchange — public but rate-limited so attackers can't brute keys.
		r.Group(func(r chi.Router) {
			r.Use(rateLimiter.Middleware())
			r.Post("/auth/token", authH.Token)
		})

		// Authenticated routes — rate-limited + JWT required.
		sinauthURL := s.config.Auth.SinauthURL
		if sinauthURL == "" {
			sinauthURL = "http://localhost:8100"
		}
		r.Group(func(r chi.Router) {
			r.Use(rateLimiter.Middleware())
			if s.Auth != nil {
				r.Use(middleware.RequireAuthWithSinauth(s.Auth, sinauthURL))
			}
			r.Get("/auth/me", authH.Me)

			// Read endpoints (any authenticated role).
			r.Get("/iocs", ioc.List)
			r.Get("/iocs/{id}", ioc.Get)
			r.Get("/iocs/{id}/correlations", corrH.ForIOC)
			r.Get("/iocs/{id}/techniques", techH.ForIOC)
			r.Get("/iocs/{id}/sightings", sightH.ForIOC)
			r.Get("/stix/bundles", stixH.ListBundles)
			r.Get("/stix/bundles/{id}", stixH.GetBundle)
			r.Get("/advisories", advisoryH.List)
			r.Get("/advisories/{id}", advisoryH.Get)
			r.Get("/feeds", feedH.List)
			r.Get("/feeds/{id}", feedH.Get)
			r.Get("/techniques", techH.List)
			r.Get("/correlations", corrH.Summary)
		})

		// Match endpoint — frequently called by ecosystem services. Rate-limited
		// but NOT JWT-gated, so APIGuard can probe without round-tripping a token
		// on every request. (In production this would typically sit behind a
		// service-mesh that adds mTLS; we keep it open here for demo purposes.)
		r.Group(func(r chi.Router) {
			r.Use(rateLimiter.Middleware())
			r.Get("/match", sightH.Match)
		})

		// Mutation endpoints — require operator role.
		if s.Auth != nil {
			r.Group(func(r chi.Router) {
				r.Use(rateLimiter.Middleware())
				r.Use(middleware.RequireRoleWithSinauth(s.Auth, auth.RoleOperator, sinauthURL))
				r.Post("/iocs", ioc.Ingest)
				r.Post("/stix/bundles", stixH.IngestBundle)
				r.Post("/advisories", advisoryH.Ingest)
				r.Post("/feeds", feedH.Create)
				r.Patch("/feeds/{id}", feedH.Patch)
				r.Delete("/feeds/{id}", feedH.Delete)
				r.Post("/sightings", sightH.Record)
			})
			// Admin-only endpoints.
			r.Group(func(r chi.Router) {
				r.Use(rateLimiter.Middleware())
				r.Use(middleware.RequireRoleWithSinauth(s.Auth, auth.RoleAdmin, sinauthURL))
				r.Get("/webhooks", webhookH.List)
				r.Post("/webhooks", webhookH.Create)
				r.Get("/webhooks/{id}", webhookH.Get)
				r.Patch("/webhooks/{id}", webhookH.Patch)
				r.Delete("/webhooks/{id}", webhookH.Delete)
				r.Get("/webhooks/{id}/deliveries", webhookH.Deliveries)
				r.Get("/webhooks/stats", webhookH.Stats)
				r.Get("/api-keys", authH.ListKeys)
				r.Post("/api-keys", authH.CreateKey)
				r.Delete("/api-keys/{id}", authH.RevokeKey)
			})
		} else {
			// Auth disabled — expose mutation endpoints without gating so dev
			// mode (empty JWT secret + no API keys) keeps working.
			r.Group(func(r chi.Router) {
				r.Use(rateLimiter.Middleware())
				r.Post("/iocs", ioc.Ingest)
				r.Post("/stix/bundles", stixH.IngestBundle)
				r.Post("/advisories", advisoryH.Ingest)
				r.Post("/feeds", feedH.Create)
				r.Patch("/feeds/{id}", feedH.Patch)
				r.Delete("/feeds/{id}", feedH.Delete)
				r.Post("/sightings", sightH.Record)
				r.Get("/webhooks", webhookH.List)
				r.Post("/webhooks", webhookH.Create)
				r.Get("/webhooks/{id}", webhookH.Get)
				r.Patch("/webhooks/{id}", webhookH.Patch)
				r.Delete("/webhooks/{id}", webhookH.Delete)
				r.Get("/webhooks/{id}/deliveries", webhookH.Deliveries)
				r.Get("/webhooks/stats", webhookH.Stats)
			})
		}
	})

	// Unused variables: the rate limiter's sweep ticker never stops; on a
	// short-lived test process that's fine.
	_ = time.Hour
}
