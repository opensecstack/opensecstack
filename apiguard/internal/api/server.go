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
	"github.com/opensecstack/sdk/go/sinauth"
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
	globalLimiter   middleware.Limiter
	authLimiter     middleware.Limiter
	scanLimiter     middleware.Limiter
	reportLimiter   middleware.Limiter
	refreshLimiter  middleware.Limiter
	apiKeyLimiter   middleware.Limiter
	secretProvider  *middleware.SecretProvider
	tokenDenylist   *middleware.TokenDenylist // access-token denylist for logout
	sinauthClient   *sinauth.Client           // nil when sinauth_url is unset
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

	sp := middleware.NewSecretProvider(cfg.Auth.EffectiveJWTSecrets()...)
	denylist := middleware.NewTokenDenylist()

	// Initialise the sinauth client for RS256 SSO token verification.
	// When APIGUARD_AUTH_SINAUTH_URL is empty the client is nil and only HS256
	// tokens are accepted. A failed initialisation is non-fatal: the server
	// starts without RS256 support and logs a warning.
	var sc2 *sinauth.Client
	if cfg.Auth.SinauthURL != "" {
		var err error
		sc2, err = sinauth.New(cfg.Auth.SinauthURL)
		if err != nil {
			logger.Warn().Err(err).Str("sinauth_url", cfg.Auth.SinauthURL).
				Msg("sinauth client init failed; RS256 tokens will be rejected")
		}
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	s := &Server{
		router:         chi.NewRouter(),
		logger:         logger,
		port:           cfg.Port,
		config:         cfg,
		db:             database,
		scanner:        sc,
		citadel:        cc,
		secretProvider: sp,
		tokenDenylist:  denylist,
		sinauthClient:  sc2,
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
		if s.tokenDenylist != nil {
			s.tokenDenylist.Stop()
		}
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
	// Deliberately NOT using chimw.RealIP: it unconditionally trusts XFF/X-Real-IP
	// from any peer and rewrites r.RemoteAddr in place, which lets a direct,
	// non-proxied attacker spoof their reported IP and poisons every downstream
	// consumer of r.RemoteAddr (rate limiters, auth logging) before they get a
	// chance to apply their own trusted-proxy allowlist. See GHSA-3fxj-6jh8-hvhx,
	// GHSA-rjr7-jggh-pgcp, GHSA-9g5q-2w5x-hmxf. Instead, r.RemoteAddr is left as
	// the real TCP peer address, and middleware.ClientIPFromRequest(WithDepth)
	// resolves the client IP itself, only trusting XFF/X-Real-IP when the direct
	// peer is in the configured trusted-proxy CIDRs.
	s.router.Use(middleware.RequestLogger(s.logger, middleware.ParseTrustedProxyCIDRs(s.config.RateLimit.TrustedProxies), s.config.RateLimit.TrustedProxyDepth))
	s.router.Use(chimw.Recoverer)
	s.router.Use(chimw.Timeout(60 * time.Second))
	s.router.Use(middleware.SecurityHeaders)
	s.router.Use(s.metrics.Middleware)
	rateLimit := s.config.Scanner.RateLimit
	if rateLimit <= 0 {
		rateLimit = 120
	}
	s.globalLimiter = middleware.NewLimiter(s.config.Redis.URL, s.config.Redis.Password, s.config.Redis.DB, rateLimit, "global", s.config.RateLimit.TrustedProxies, s.config.RateLimit.TrustedProxyDepth)
	s.router.Use(s.globalLimiter.Middleware)             // requests per minute per IP
	s.router.Use(middleware.CORS(s.config.CORS.Origins)) // CORS must run before JWT auth
}

func (s *Server) registerRoutes() {
	h := handlers.NewHealthWithDB(s.logger, s.db)
	a := handlers.NewAuthWithDB(s.logger, s.config, s.db, s.citadel, s.secretProvider, s.tokenDenylist)
	sc := handlers.NewScansWithCitadel(s.logger, s.db, s.scanner, s.citadel, s.shutdownCtx, s.config)
	s.scansHandler = sc // store for WaitScans() on shutdown
	f := handlers.NewFindingsWithCitadel(s.logger, s.db, s.citadel, s.config)
	specsH := handlers.NewSpecs(s.logger, "")
	au := handlers.NewAudit(s.logger, s.db)
	ak := handlers.NewAPIKeys(s.logger, s.db, s.citadel, s.config)
	inv := handlers.NewInventory(s.logger, s.db)
	wh := handlers.NewWebhooks(s.logger, s.config.Citadel.WebhookSecret, s.shutdownCancel)

	// Create per-route limiters here so they can be stopped on shutdown.
	proxies := s.config.RateLimit.TrustedProxies
	depth := s.config.RateLimit.TrustedProxyDepth
	redisURL := s.config.Redis.URL
	redisPass := s.config.Redis.Password
	redisDB := s.config.Redis.DB
	s.authLimiter = middleware.NewLimiter(redisURL, redisPass, redisDB, 20, "auth", proxies, depth)
	s.scanLimiter = middleware.NewLimiter(redisURL, redisPass, redisDB, 60, "scan", proxies, depth)
	s.reportLimiter = middleware.NewLimiter(redisURL, redisPass, redisDB, 10, "report", proxies, depth)
	s.refreshLimiter = middleware.NewLimiter(redisURL, redisPass, redisDB, 20, "refresh", proxies, depth)
	s.apiKeyLimiter = middleware.NewLimiter(redisURL, redisPass, redisDB, 5, "apikey", proxies, depth)

	RegisterRoutes(s.router, h, a, sc, f, specsH, au, ak, inv, wh, s.metrics, s.config, s.authLimiter, s.scanLimiter, s.reportLimiter, s.refreshLimiter, s.apiKeyLimiter, s.secretProvider, s.tokenDenylist, s.sinauthClient, middleware.ParseTrustedProxyCIDRs(s.config.RateLimit.TrustedProxies))
}
