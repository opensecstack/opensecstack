package api

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
)

// Server is the APIGuard HTTP server.
type Server struct {
	router chi.Router
	logger zerolog.Logger
	port   int
	config *config.Config
}

// NewServer creates a new API server with routes registered.
func NewServer(cfg *config.Config) *Server {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Str("component", "api").
		Logger()

	s := &Server{
		router: chi.NewRouter(),
		logger: logger,
		port:   cfg.Port,
		config: cfg,
	}

	s.setupMiddleware()
	s.registerRoutes()

	return s
}

// Start begins listening for HTTP requests.
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

	return srv.ListenAndServe()
}

// Router returns the chi router for testing.
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) setupMiddleware() {
	s.router.Use(chimw.RequestID)
	s.router.Use(chimw.RealIP)
	s.router.Use(middleware.RequestLogger(s.logger))
	s.router.Use(chimw.Recoverer)
	s.router.Use(chimw.Timeout(60 * time.Second))
}

func (s *Server) registerRoutes() {
	h := handlers.NewHealth(s.logger)
	sc := handlers.NewScans(s.logger)
	f := handlers.NewFindings(s.logger)

	RegisterRoutes(s.router, h, sc, f, s.config)
}
