package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/citadel"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/scanner"
)

// Server is the APIGuard HTTP server.
type Server struct {
	router          chi.Router
	logger          zerolog.Logger
	port            int
	config          *config.Config
	db              *db.DB
	scanner         *scanner.Scanner
	citadel         *citadel.Client
	globalLimiter   *middleware.RateLimiter
	authLimiter     *middleware.RateLimiter
	scanLimiter     *middleware.RateLimiter
	reportLimiter   *middleware.RateLimiter
	refreshLimiter  *middleware.RateLimiter
	apiKeyLimiter   *middleware.RateLimiter
	metrics         *middleware.MetricsCollector
	shutdownCtx     context.Context
	shutdownCancel  context.CancelFunc
	scansHandler    *handlers.Scans // kept for WaitScans() on shutdown
	stopAuditWorker func()          // M6: stops the background audit worker goroutine
}

// NewServer creates a new API server with routes registered.
func NewServer(cfg *config.Config, database *db.DB, sc *scanner.Scanner) *Server {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Str("component", "api").
		Logger()

	// Initialise the CITADEL client. When APIGUARD_CITADEL_URL is unset the
	// client is a no-op — all EvaluateScan/EmitWORM/LogEvent calls return immediately.
	cc := citadel.New(cfg.Citadel.APIURL, cfg.Citadel.KeyID, cfg.Citadel.KeySecret)

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	s := &Server{
		router:         chi.NewRouter(),
		logger:         logger,
		port:           cfg.Port,
		config:         cfg,
		db:             database,
		scanner:        sc,
		citadel:        cc,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}

	s.metrics = middleware.NewMetricsCollector()
	s.setupMiddleware()
	s.registerRoutes()

	// M6: start the background audit worker so all AppendAuditLog calls are
	// processed asynchronously and FlushAuditLog can drain them on shutdown.
	s.stopAuditWorker = db.StartAuditWorker(database.Pool)

	return s
}

// Start begins listening for HTTP requests and shuts down gracefully on SIGINT/SIGTERM.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	s.logger.Info().Str("addr", addr).Msg("API server listening")

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Capture SIGINT / SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		stop() // release signal resources promptly
		s.shutdownCancel()
		s.logger.Info().Msg("shutdown signal received — draining connections")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		// A-H2: wait for in-flight scan goroutines to complete (or time out).
		if s.scansHandler != nil {
			scanWaitCtx, scanWaitCancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer scanWaitCancel()
			scansDone := make(chan struct{})
			go func() {
				s.scansHandler.WaitScans()
				close(scansDone)
			}()
			select {
			case <-scansDone:
			case <-scanWaitCtx.Done():
				s.logger.Warn().Msg("timed out waiting for in-flight scans to complete")
			}
		}
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer drainCancel()
		s.citadel.Drain(drainCtx)
		if drainCtx.Err() != nil {
			s.logger.Warn().Msg("CITADEL drain timed out — some audit events may not have been forwarded")
		}
		// M6: flush any pending audit log entries before closing the DB pool.
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer flushCancel()
		if err := db.FlushAuditLog(flushCtx); err != nil {
			s.logger.Warn().Err(err).Msg("audit log flush timed out on shutdown")
		}
		if s.stopAuditWorker != nil {
			s.stopAuditWorker()
		}
		s.globalLimiter.Stop()
		s.authLimiter.Stop()
		s.scanLimiter.Stop()
		s.reportLimiter.Stop()
		s.refreshLimiter.Stop()
		s.apiKeyLimiter.Stop()
		s.db.Close()
		s.logger.Info().Msg("server stopped cleanly")
		return nil
	}
}

// Router returns the chi router for testing.
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) setupMiddleware() {
	s.router.Use(middleware.CorrelationID) // must be first so all subsequent middleware can read the correlation ID
	s.router.Use(chimw.RequestID)
	s.router.Use(chimw.RealIP)
	s.router.Use(middleware.RequestLogger(s.logger, middleware.ParseTrustedProxyCIDRs(s.config.RateLimit.TrustedProxies)))
	s.router.Use(chimw.Recoverer)
	s.router.Use(chimw.Timeout(60 * time.Second))
	s.router.Use(middleware.SecurityHeaders)
	s.router.Use(s.metrics.Middleware)
	rateLimit := s.config.Scanner.RateLimit
	if rateLimit <= 0 {
		rateLimit = 120
	}
	s.globalLimiter = middleware.NewRateLimiterWithProxies(rateLimit, s.config.RateLimit.TrustedProxies)
	s.router.Use(s.globalLimiter.Middleware) // requests per minute per IP
	s.router.Use(middleware.CORS(s.config.CORS.Origins)) // CORS must run before JWT auth
}

func (s *Server) registerRoutes() {
	h := handlers.NewHealth(s.logger)
	a := handlers.NewAuthWithDB(s.logger, s.config, s.db)
	sc := handlers.NewScansWithCitadel(s.logger, s.db, s.scanner, s.citadel, s.shutdownCtx, s.config)
	s.scansHandler = sc // store for WaitScans() on shutdown
	f := handlers.NewFindingsWithCitadel(s.logger, s.db, s.citadel, s.config)
	sp := handlers.NewSpecs(s.logger, "")
	au := handlers.NewAudit(s.logger, s.db)
	ak := handlers.NewAPIKeys(s.logger, s.db, s.citadel, s.config)
	inv := handlers.NewInventory(s.logger, s.db)

	// Create per-route limiters here so they can be stopped on shutdown.
	s.authLimiter = middleware.NewRateLimiter(20)    // 20 req/min per IP on auth endpoints
	s.scanLimiter = middleware.NewRateLimiter(60)    // 60 req/min per IP on scan creation
	s.reportLimiter = middleware.NewRateLimiter(10)  // 10 req/min per IP on report generation
	s.refreshLimiter = middleware.NewRateLimiter(20) // 20 req/min per IP on refresh revocation
	s.apiKeyLimiter = middleware.NewRateLimiter(5)   // 5 req/min per IP on API key creation

	RegisterRoutes(s.router, h, a, sc, f, sp, au, ak, inv, s.metrics, s.config, s.authLimiter, s.scanLimiter, s.reportLimiter, s.refreshLimiter, s.apiKeyLimiter, middleware.ParseTrustedProxyCIDRs(s.config.RateLimit.TrustedProxies))
}
