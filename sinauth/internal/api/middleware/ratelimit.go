package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipEntry struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// RateLimiter holds isolated state for one rate-limit policy.
// Each call to RateLimit() returns a middleware backed by a separate instance,
// so auth and global counters never bleed into each other.
type RateLimiter struct {
	entries sync.Map
	limit   int
	window  time.Duration
	trusted map[string]struct{}
}

func newRateLimiter(limit int, window time.Duration, trustedProxies []string) *RateLimiter {
	trusted := make(map[string]struct{}, len(trustedProxies))
	for _, p := range trustedProxies {
		trusted[strings.TrimSpace(p)] = struct{}{}
	}
	rl := &RateLimiter{limit: limit, window: window, trusted: trusted}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.window)
		rl.entries.Range(func(key, val any) bool {
			e := val.(*ipEntry)
			e.mu.Lock()
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
				rl.entries.Delete(key)
			}
			return true
		})
	}
}

func (rl *RateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, rl.trusted)
		now := time.Now()
		cutoff := now.Add(-rl.window)

		val, _ := rl.entries.LoadOrStore(ip, &ipEntry{})
		e := val.(*ipEntry)
		e.mu.Lock()
		n := 0
		for _, t := range e.timestamps {
			if t.After(cutoff) {
				e.timestamps[n] = t
				n++
			}
		}
		e.timestamps = e.timestamps[:n]
		if len(e.timestamps) >= rl.limit {
			e.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many requests"})
			return
		}
		e.timestamps = append(e.timestamps, now)
		e.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// RateLimit returns a middleware that limits requests to limit per window per client IP.
// Each call creates an isolated limiter — counters are not shared between instances.
func RateLimit(limit int, window time.Duration, trustedProxies ...string) func(http.Handler) http.Handler {
	rl := newRateLimiter(limit, window, trustedProxies)
	return rl.middleware
}

func clientIP(r *http.Request, trustedSet map[string]struct{}) string {
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
