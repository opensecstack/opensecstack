package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiter holds the state for an in-memory sliding-window rate limiter.
type RateLimiter struct {
	mu             sync.Mutex
	visitors       map[string]*rlVisitor
	rate           int           // maximum requests allowed per window
	window         time.Duration // window duration
	trustedProxies []*net.IPNet  // upstream proxy IPs whose XFF header is trusted
	done           chan struct{}  // closed by Stop() to signal the cleanup goroutine to exit
}

type rlVisitor struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a RateLimiter that allows requestsPerMinute requests
// per 60-second sliding window per client IP.
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	return NewRateLimiterWithProxies(requestsPerMinute, nil)
}

// NewRateLimiterWithProxies creates a RateLimiter that only trusts the
// X-Forwarded-For header when the direct peer (r.RemoteAddr) is one of the
// listed trusted proxy CIDRs. Pass nil or an empty slice to always use
// RemoteAddr directly (safe default).
func NewRateLimiterWithProxies(requestsPerMinute int, trustedProxyCIDRs []string) *RateLimiter {
	var nets []*net.IPNet
	for _, cidr := range trustedProxyCIDRs {
		// Accept plain IPs as well as CIDR blocks.
		if !containsSlash(cidr) {
			cidr = cidr + "/32"
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}

	rl := &RateLimiter{
		visitors:       make(map[string]*rlVisitor),
		rate:           requestsPerMinute,
		window:         time.Minute,
		trustedProxies: nets,
		done:           make(chan struct{}),
	}

	// Background goroutine cleans up expired visitor entries every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.mu.Lock()
				now := time.Now()
				for ip, v := range rl.visitors {
					if now.After(v.resetAt) {
						delete(rl.visitors, ip)
					}
				}
				rl.mu.Unlock()
			case <-rl.done:
				return
			}
		}
	}()

	return rl
}

// Stop signals the background cleanup goroutine to exit. It should be called
// when the RateLimiter is no longer needed to prevent goroutine leaks.
func (rl *RateLimiter) Stop() {
	close(rl.done)
}

// Middleware returns an http.Handler middleware that enforces the rate limit.
// Clients are identified by their IP address (X-Forwarded-For only when the
// direct peer is a trusted proxy, otherwise RemoteAddr).
// On limit exceeded it returns HTTP 429 with a JSON body and Retry-After header.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)

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
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
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

// ClientIPFromRequest extracts the real client IP using the same trusted-proxy
// logic as the RateLimiter. X-Forwarded-For is only honoured when the direct
// peer (r.RemoteAddr) is one of the provided trustedProxies. Pass nil to always
// use RemoteAddr.
func ClientIPFromRequest(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if len(trustedProxies) > 0 {
		remoteIP := net.ParseIP(remoteHost)
		if remoteIP != nil {
			for _, ipNet := range trustedProxies {
				if ipNet.Contains(remoteIP) {
					if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
						ip := xff
						if idx := indexByte(xff, ','); idx >= 0 {
							ip = xff[:idx]
						}
						ip = trimSpace(ip)
						if ip != "" {
							return ip
						}
					}
					break
				}
			}
		}
	}

	return remoteHost
}

// clientIP extracts the real client IP. X-Forwarded-For is only trusted when
// the direct connection peer (r.RemoteAddr) is in the configured trusted proxy
// list. When no trusted proxies are configured, RemoteAddr is always used.
func (rl *RateLimiter) clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	// Only trust XFF if the direct peer is a known trusted proxy.
	if len(rl.trustedProxies) > 0 {
		remoteIP := net.ParseIP(remoteHost)
		if remoteIP != nil && rl.isTrustedProxy(remoteIP) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// X-Forwarded-For may be comma-separated; take the first (leftmost) entry.
				ip := xff
				if idx := indexByte(xff, ','); idx >= 0 {
					ip = xff[:idx]
				}
				ip = trimSpace(ip)
				if ip != "" {
					return ip
				}
			}
		}
	}

	return remoteHost
}

// isTrustedProxy reports whether ip is within one of the configured proxy ranges.
func (rl *RateLimiter) isTrustedProxy(ip net.IP) bool {
	for _, net := range rl.trustedProxies {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// containsSlash reports whether s contains a '/' character (used to detect CIDRs).
func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

// indexByte returns the index of the first occurrence of b in s, or -1.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// trimSpace removes leading and trailing ASCII spaces from s.
func trimSpace(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}
