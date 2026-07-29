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

	"github.com/opensecstack/citadel/internal/api/handlers"
	"github.com/opensecstack/citadel/internal/auth"
	"github.com/opensecstack/citadel/internal/config"
	"github.com/opensecstack/citadel/internal/db"
	"github.com/opensecstack/citadel/internal/marshal"
	"github.com/opensecstack/citadel/internal/permifysync"
)

// Server is the CITADEL HTTP server.
type Server struct {
	router          chi.Router
	logger          zerolog.Logger
	port            int
	db              *db.DB
	cfg             *config.Config
	verifier        *auth.SinauthVerifier
	permifySnapshot *permifysync.Snapshot
}

// NewServer creates a new CITADEL server with all routes registered. Fails
// if a sinauth verifier cannot be constructed — an AuthN gate with no way
// to verify tokens is a worse failure mode than refusing to start (see
// adrs/005-sinauth-identity-bridge.md).
//
// permifySnapshot is the in-memory Gate 2 Permify snapshot maintained by
// cmd/citadel/main.go's internal/permifysync background sync; nil when
// cfg.Citadel.PermifyURL is unset, in which case Gate 2's Permify sub-check
// is a no-op PASS for every role/action — see
// adrs/007-permify-gate2-snapshot.md.
func NewServer(cfg *config.Config, database *db.DB, permifySnapshot *permifysync.Snapshot) (*Server, error) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Str("component", "citadel-api").
		Logger()

	verifier, err := auth.NewSinauthVerifier(cfg.Citadel.SinauthIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("citadel: constructing sinauth verifier: %w", err)
	}

	s := &Server{
		router:          chi.NewRouter(),
		logger:          logger,
		port:            cfg.Port,
		db:              database,
		cfg:             cfg,
		verifier:        verifier,
		permifySnapshot: permifySnapshot,
	}

	s.setupMiddleware()
	s.registerRoutes()
	return s, nil
}

// Start begins listening for HTTP requests and shuts down gracefully on SIGINT/SIGTERM.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	s.logger.Info().Str("addr", addr).Msg("CITADEL governance engine listening")

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

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
		stop()
		s.logger.Info().Msg("shutdown signal received — draining connections")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		if s.db != nil {
			s.db.Close()
		}
		s.logger.Info().Msg("CITADEL server stopped cleanly")
		return nil
	}
}

// Router returns the chi router (for testing).
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) setupMiddleware() {
	s.router.Use(chimw.RequestID)
	s.router.Use(chimw.RealIP)
	s.router.Use(chimw.Logger)
	s.router.Use(chimw.Recoverer)
	s.router.Use(chimw.Timeout(60 * time.Second))
	s.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			next.ServeHTTP(w, r)
		})
	})
}

func (s *Server) registerRoutes() {
	health := handlers.NewHealth(s.logger, s.db)
	worm := handlers.NewWORM(s.logger, s.db)
	keys := handlers.NewKeys(s.logger, s.db, s.verifier)

	// MARSHAL engine uses MarshalStore adapter (breaks db↔marshal import cycle)
	engine := marshal.New(db.NewMarshalStore(s.db), s.verifier).
		EnforceIdentity(s.cfg.Citadel.EnforceIdentity).
		EnforceSignatures(s.cfg.Citadel.EnforceSignatures).
		EnforcePermifyAuthz(s.cfg.Citadel.EnforcePermifyAuthz)
	if s.permifySnapshot != nil {
		// Only wire a real snapshot in — a nil *permifysync.Snapshot must
		// never be handed to marshal.PermifySnapshot as a non-nil
		// interface value (that would make Gate 2's nil check pass a
		// non-nil interface wrapping a nil pointer, panicking on first
		// Allowed() call). Engine's default (no snapshot wired) already
		// behaves as "known=false for everything" — see
		// adrs/007-permify-gate2-snapshot.md.
		engine = engine.PermifySnapshot(s.permifySnapshot)
	}
	marshalH := handlers.NewMarshal(s.logger, engine)

	s.router.Get("/api/v1/health", health.ServeHTTP)
	s.router.Post("/api/v1/marshal/evaluate", marshalH.ServeHTTP)
	s.router.Post("/api/v1/worm/emit", worm.Emit)
	s.router.Get("/api/v1/worm/verify", worm.Verify)
	s.router.Post("/api/v1/keys/register", keys.Register)
	s.router.Get("/api/v1/keys/{user_id}", keys.Get)
}
