package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter is a per-IP token-bucket limiter. Entries idle longer than
// `sweepInterval` are garbage-collected so long-running servers do not leak
// memory for clients that visit once.
type RateLimiter struct {
	rps   rate.Limit
	burst int

	mu       sync.Mutex
	visitors map[string]*visitor

	ttl           time.Duration
	sweepInterval time.Duration
}

type visitor struct {
	limiter *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter builds a limiter allowing `rps` requests per second per IP
// with a burst of `burst`.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		rps:           rate.Limit(rps),
		burst:         burst,
		visitors:      make(map[string]*visitor),
		ttl:           10 * time.Minute,
		sweepInterval: time.Minute,
	}
	go rl.sweep()
	return rl
}

// Middleware enforces the limit on every request. Requests over the limit
// receive HTTP 429 with a short JSON body and a Retry-After header.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.allow(ip) {
				w.Header().Set("Retry-After", "1")
				writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

func (rl *RateLimiter) sweep() {
	ticker := time.NewTicker(rl.sweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.ttl)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if v.lastSeen.Before(cutoff) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func clientIP(r *http.Request) string {
	// chi's RealIP middleware normalises X-Forwarded-For into r.RemoteAddr,
	// so take whatever is in RemoteAddr and strip the :port suffix.
	addr := r.RemoteAddr
	if idx := indexPort(addr); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

// indexPort returns the position of the final colon separating host and port,
// handling both IPv4 and bracketed IPv6 forms.
func indexPort(addr string) int {
	if addr == "" {
		return -1
	}
	if addr[0] == '[' {
		// [::1]:port
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				return i
			}
		}
		return -1
	}
	colons := 0
	for _, c := range addr {
		if c == ':' {
			colons++
		}
	}
	if colons == 1 {
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				return i
			}
		}
	}
	return -1
}
