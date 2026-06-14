package middleware

// Usage in server.go:
//
// Strict limit for auth endpoints (5 req/min per IP):
//
//	authRL := middleware.RateLimit(5, time.Minute)
//	mux.Handle("POST /api/v1/auth/login",          authRL(http.HandlerFunc(handlers.Login(d))))
//	mux.Handle("POST /api/v1/auth/register",        authRL(http.HandlerFunc(handlers.Register(d))))
//	mux.Handle("POST /api/v1/auth/forgot-password", authRL(http.HandlerFunc(handlers.ForgotPassword(d))))
//	mux.Handle("POST /api/v1/auth/reset-password",  authRL(http.HandlerFunc(handlers.ResetPassword(d))))
//
// General API limit (120 req/min per IP) applied to the whole mux at the end:
//
//	return middleware.CORS(middleware.Logger(middleware.RateLimit(120, time.Minute)(mux)))

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipEntry tracks request timestamps for a single client IP.
type ipEntry struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// rateLimiter holds the per-IP state map and the cleanup trigger.
type rateLimiter struct {
	entries sync.Map // map[string]*ipEntry
}

// package-level singleton for the background cleanup goroutine.
var (
	cleanupOnce sync.Once
	globalRL    = &rateLimiter{}
)

// startCleanup launches a single background goroutine that evicts stale entries
// from the shared map every minute. It is started at most once per process.
func startCleanup(window time.Duration) {
	cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				cutoff := time.Now().Add(-window)
				globalRL.entries.Range(func(key, val any) bool {
					e := val.(*ipEntry)
					e.mu.Lock()
					// Drop all timestamps older than the window.
					n := 0
					for _, t := range e.timestamps {
						if t.After(cutoff) {
							e.timestamps[n] = t
							n++
						}
					}
					e.timestamps = e.timestamps[:n]
					empty := len(e.timestamps) == 0
					e.mu.Unlock()
					if empty {
						globalRL.entries.Delete(key)
					}
					return true
				})
			}
		}()
	})
}

// clientIPWithTrust extracts the real client IP from the request.
// X-Forwarded-For is only honoured when the direct connection IP (r.RemoteAddr)
// is present in trustedSet, preventing spoofing from untrusted clients.
func clientIPWithTrust(r *http.Request, trustedSet map[string]struct{}) string {
	addr := r.RemoteAddr
	host, _, _ := strings.Cut(addr, ":")
	if _, trusted := trustedSet[host]; trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	return host
}

// clientIP extracts the real client IP from the request without trusting any
// proxy headers. Kept for backward compatibility with other callers.
func clientIP(r *http.Request) string {
	return clientIPWithTrust(r, map[string]struct{}{})
}

// RateLimit returns middleware that allows at most limit requests per window
// duration per IP. When the limit is exceeded it responds 429 with JSON
// {"error":"too many requests"}.
//
// trustedProxies is an optional list of proxy IP addresses whose
// X-Forwarded-For headers are trusted for real-IP resolution. Any
// X-Forwarded-For header arriving from an address not in this list is ignored,
// preventing IP spoofing to bypass per-IP rate limits.
func RateLimit(limit int, window time.Duration, trustedProxies ...string) func(http.Handler) http.Handler {
	startCleanup(window)

	trustedSet := make(map[string]struct{}, len(trustedProxies))
	for _, p := range trustedProxies {
		trustedSet[p] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIPWithTrust(r, trustedSet)
			now := time.Now()
			cutoff := now.Add(-window)

			// Load or create the entry for this IP.
			val, _ := globalRL.entries.LoadOrStore(ip, &ipEntry{})
			e := val.(*ipEntry)

			e.mu.Lock()
			// Evict timestamps outside the sliding window.
			n := 0
			for _, t := range e.timestamps {
				if t.After(cutoff) {
					e.timestamps[n] = t
					n++
				}
			}
			e.timestamps = e.timestamps[:n]

			if len(e.timestamps) >= limit {
				e.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many requests"})
				return
			}

			e.timestamps = append(e.timestamps, now)
			e.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
