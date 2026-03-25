package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/scanner"
)

// Server is the APIGuard HTTP server.
type Server struct {
	router  chi.Router
	logger  zerolog.Logger
	port    int
	config  *config.Config
	db      *db.DB
	scanner *scanner.Scanner
}

// NewServer creates a new API server with routes registered.
func NewServer(cfg *config.Config, database *db.DB, sc *scanner.Scanner) *Server {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Str("component", "api").
		Logger()

	s := &Server{
		router:  chi.NewRouter(),
		logger:  logger,
		port:    cfg.Port,
		config:  cfg,
		db:      database,
		scanner: sc,
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
	s.router.Use(RateLimiter(context.Background(), 120)) // 120 requests per minute per IP
	s.router.Use(CORSMiddleware(nil))                    // No cross-origin allowed by default (same-origin only)
}

func (s *Server) registerRoutes() {
	h := handlers.NewHealth(s.logger)
	a := handlers.NewAuth(s.logger, s.config)
	sc := handlers.NewScans(s.logger, s.db, s.scanner)
	f := handlers.NewFindings(s.logger, s.db)
	sp := handlers.NewSpecs(s.logger, "")

	RegisterRoutes(s.router, h, a, sc, f, sp, s.config)
}

// RateLimiter returns a middleware that limits requests per IP using a sliding window.
func RateLimiter(ctx context.Context, requestsPerMinute int) func(http.Handler) http.Handler {
	const maxVisitors = 100000

	type visitor struct {
		count   int
		resetAt time.Time
	}
	var mu sync.Mutex
	visitors := make(map[string]*visitor)

	// Cleanup old entries every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for ip, v := range visitors {
					if now.After(v.resetAt) {
						delete(visitors, ip)
					}
				}
				mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use RemoteAddr only (chimw.RealIP already normalizes it)
			// Strip port to avoid per-connection buckets
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			mu.Lock()
			v, exists := visitors[ip]
			now := time.Now()
			if !exists || now.After(v.resetAt) {
				if !exists && len(visitors) >= maxVisitors {
					mu.Unlock()
					w.Header().Set("Retry-After", "60")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					json.NewEncoder(w).Encode(map[string]string{"error": "too_many_clients", "message": "Too many clients. Try again later."})
					return
				}
				visitors[ip] = &visitor{count: 1, resetAt: now.Add(time.Minute)}
				mu.Unlock()
				next.ServeHTTP(w, r)
				return
			}
			v.count++
			if v.count > requestsPerMinute {
				mu.Unlock()
				w.Header().Set("Retry-After", "60")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{"error": "rate_limit_exceeded", "message": "Too many requests. Try again later."})
				return
			}
			mu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware returns a middleware that sets CORS headers for allowed origins.
// If allowedOrigins is nil or empty, no CORS headers are set (same-origin only).
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range allowedOrigins {
				if o == origin || o == "*" {
					allowed = true
					break
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
			if r.Method == "OPTIONS" && allowed {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
