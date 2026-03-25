package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter holds the state for an in-memory sliding-window rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rlVisitor
	rate     int           // maximum requests allowed per window
	window   time.Duration // window duration
}

type rlVisitor struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a RateLimiter that allows requestsPerMinute requests
// per 60-second sliding window per client IP.
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*rlVisitor),
		rate:     requestsPerMinute,
		window:   time.Minute,
	}

	// Background goroutine cleans up expired visitor entries every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			for ip, v := range rl.visitors {
				if now.After(v.resetAt) {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()

	return rl
}

// Middleware returns an http.Handler middleware that enforces the rate limit.
// Clients are identified by their IP address (X-Forwarded-For / RemoteAddr).
// On limit exceeded it returns HTTP 429 with a JSON body and Retry-After header.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		rl.mu.Lock()
		v, exists := rl.visitors[ip]
		now := time.Now()
		if !exists || now.After(v.resetAt) {
			rl.visitors[ip] = &rlVisitor{count: 1, resetAt: now.Add(rl.window)}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}
		v.count++
		if v.count > rl.rate {
			rl.mu.Unlock()
			retryAfter := int(time.Until(v.resetAt).Seconds())
			if retryAfter < 1 {
				retryAfter = 60
			}
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":       "Rate limit exceeded",
				"code":        "RATE_LIMITED",
				"retry_after": retryAfter,
			})
			return
		}
		rl.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the client IP from X-Forwarded-For (first entry) or
// RemoteAddr, stripping any port suffix.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may contain a comma-separated list; use the first.
		if idx := len(xff); idx > 0 {
			for i, c := range xff {
				if c == ',' {
					idx = i
					break
				}
			}
			ip := xff[:idx]
			// trim whitespace
			for len(ip) > 0 && ip[0] == ' ' {
				ip = ip[1:]
			}
			for len(ip) > 0 && ip[len(ip)-1] == ' ' {
				ip = ip[:len(ip)-1]
			}
			if ip != "" {
				return ip
			}
		}
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
