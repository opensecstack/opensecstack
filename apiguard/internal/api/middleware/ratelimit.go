package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Limiter is the interface satisfied by both RateLimiter and RedisRateLimiter.
// Server and route registration code uses this interface so implementations
// can be swapped without changing caller code.
type Limiter interface {
	Middleware(next http.Handler) http.Handler
	Stop()
}

// RateLimiter holds the state for an in-memory sliding-window rate limiter.
type RateLimiter struct {
	mu             sync.Mutex
	visitors       map[string]*rlVisitor
	rate           int           // maximum requests allowed per window
	window         time.Duration // window duration
	trustedProxies []*net.IPNet  // upstream proxy IPs whose XFF header is trusted
	proxyDepth     int           // number of proxy hops to skip in XFF (≥1)
	done           chan struct{}  // closed by Stop() to signal the cleanup goroutine to exit
	stopOnce       sync.Once     // ensures Stop() is idempotent
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

// MustParseTrustedProxyCIDRs parses a list of CIDR strings (or plain IPs,
// treated as /32) into a slice of *net.IPNet values. Invalid entries are
// skipped and a WARN-level message is emitted via logger for each bad entry.
// Pass slog.Default() to use the process-wide logger, or a custom logger for
// component-scoped output. This is the canonical implementation shared by the
// rate limiter, request logger, and handler packages.
func MustParseTrustedProxyCIDRs(cidrs []string, logger *slog.Logger) []*net.IPNet {
	var nets []*net.IPNet
	for _, raw := range cidrs {
		cidr := raw
		if !containsSlash(cidr) {
			cidr = cidr + "/32"
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Warn("trusted proxy CIDR is invalid and will be ignored",
				slog.String("entry", raw),
				slog.String("error", err.Error()),
			)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// ParseTrustedProxyCIDRs parses a list of CIDR strings (or plain IPs, which are
// treated as /32) into a slice of *net.IPNet values. Invalid entries are silently
// skipped. Prefer MustParseTrustedProxyCIDRs when a logger is available so that
// misconfigured entries surface as warnings rather than disappearing silently.
func ParseTrustedProxyCIDRs(cidrs []string) []*net.IPNet {
	return MustParseTrustedProxyCIDRs(cidrs, slog.New(discardSlogHandler{}))
}

// discardSlogHandler is a slog.Handler that discards all log records, used
// internally by ParseTrustedProxyCIDRs to satisfy the logger parameter of
// MustParseTrustedProxyCIDRs without emitting any output.
type discardSlogHandler struct{}

func (discardSlogHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardSlogHandler) Handle(_ context.Context, _ slog.Record) error  { return nil }
func (discardSlogHandler) WithAttrs(_ []slog.Attr) slog.Handler           { return discardSlogHandler{} }
func (discardSlogHandler) WithGroup(_ string) slog.Handler                { return discardSlogHandler{} }

// NewRateLimiterWithProxies creates a RateLimiter that only trusts the
// X-Forwarded-For header when the direct peer (r.RemoteAddr) is one of the
// listed trusted proxy CIDRs. Pass nil or an empty slice to always use
// RemoteAddr directly (safe default). proxyDepth ≥ 1 controls how many hops
// to skip from the right of XFF; values < 1 are clamped to 1.
func NewRateLimiterWithProxies(requestsPerMinute int, trustedProxyCIDRs []string) *RateLimiter {
	return NewRateLimiterWithProxiesAndDepth(requestsPerMinute, trustedProxyCIDRs, 1)
}

// NewRateLimiterWithProxiesAndDepth is like NewRateLimiterWithProxies but also
// accepts a proxyDepth that controls how many XFF hops to skip. Use depth > 1
// when multiple trusted proxies are chained (e.g. an external LB in front of
// an nginx ingress).
func NewRateLimiterWithProxiesAndDepth(requestsPerMinute int, trustedProxyCIDRs []string, proxyDepth int) *RateLimiter {
	nets := ParseTrustedProxyCIDRs(trustedProxyCIDRs)
	if proxyDepth < 1 {
		proxyDepth = 1
	}

	rl := &RateLimiter{
		visitors:       make(map[string]*rlVisitor),
		rate:           requestsPerMinute,
		window:         time.Minute,
		trustedProxies: nets,
		proxyDepth:     proxyDepth,
		done:           make(chan struct{}),
	}

	// Background goroutine cleans up expired visitor entries. The interval is
	// adaptive: it starts at 5 minutes and is halved (min 30s) when the
	// retained count exceeds 10 000, or doubled (max 10 minutes) when it
	// falls below 100, so the cleanup frequency tracks actual load.
	go func() {
		const (
			minInterval     = 30 * time.Second
			maxInterval     = 10 * time.Minute
			defaultInterval = 5 * time.Minute
		)
		interval := defaultInterval
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.mu.Lock()
				now := time.Now()
				removed, retained := 0, 0
				for ip, v := range rl.visitors {
					if now.After(v.resetAt) {
						delete(rl.visitors, ip)
						removed++
					} else {
						retained++
					}
				}
				rl.mu.Unlock()

				// Adapt the cleanup interval based on how many entries remain.
				_ = removed // acknowledged; retained drives the decision
				newInterval := interval
				if retained > 10000 {
					newInterval = interval / 2
					if newInterval < minInterval {
						newInterval = minInterval
					}
				} else if retained < 100 {
					newInterval = interval * 2
					if newInterval > maxInterval {
						newInterval = maxInterval
					}
					// M2: cap at 5 minutes regardless of maxInterval so stale
					// visitor entries are never retained longer than 5 minutes
					// under zero-traffic conditions.
					if newInterval > 5*time.Minute {
						newInterval = 5 * time.Minute
					}
				}
				if newInterval != interval {
					interval = newInterval
					ticker.Reset(interval)
				}
			case <-rl.done:
				return
			}
		}
	}()

	return rl
}

// Stop signals the background cleanup goroutine to exit. It should be called
// when the RateLimiter is no longer needed to prevent goroutine leaks.
// Stop is idempotent — it is safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.done) })
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

// ClientIPFromRequest extracts the real client IP using trusted-proxy logic.
//
// Resolution order when the direct peer is a trusted proxy:
//  1. X-Forwarded-For (depth-aware): XFF is a left-to-right append chain —
//     the original client IP is leftmost, each proxy adds its own IP to the
//     right. depth is the number of trusted proxy hops that will have appended
//     to XFF. The real client is therefore at index max(0, len-1-depth) from
//     the left. Examples:
//       XFF="client, proxy1"          depth=1 → parts[max(0,2-1-1)=0] = "client"
//       XFF="client, proxy1, proxy2"  depth=2 → parts[max(0,3-1-2)=0] = "client"
//       XFF="client, proxy1, proxy2"  depth=1 → parts[max(0,3-1-1)=1] = "proxy1"
//     If depth exceeds the list length the leftmost (index 0) entry is returned.
//  2. X-Real-IP: accepted as a fallback when no XFF header is present (common
//     with nginx upstreams that set only X-Real-IP).
//  3. RemoteAddr: always used when no trusted proxy matches or no proxy header
//     yields a non-empty value.
//
// Pass nil trustedProxies to always use RemoteAddr (safe default).
// depth < 1 is treated as 1.
func ClientIPFromRequest(r *http.Request, trustedProxies []*net.IPNet) string {
	return clientIPFromRequestWithDepth(r, trustedProxies, 1)
}

// ClientIPFromRequestWithDepth is like ClientIPFromRequest but also accepts a
// proxyDepth for multi-hop XFF stripping. Use depth > 1 when multiple trusted
// proxies are chained. depth < 1 is clamped to 1.
func ClientIPFromRequestWithDepth(r *http.Request, trustedProxies []*net.IPNet, depth int) string {
	return clientIPFromRequestWithDepth(r, trustedProxies, depth)
}

// clientIPFromRequestWithDepth is the single shared implementation used by
// both the exported helpers and the RateLimiter's internal method.
func clientIPFromRequestWithDepth(r *http.Request, trustedProxies []*net.IPNet, depth int) string {
	if depth < 1 {
		depth = 1
	}

	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if len(trustedProxies) == 0 {
		return remoteHost
	}

	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || !isTrustedProxyIP(remoteIP, trustedProxies) {
		return remoteHost
	}

	// Peer is a trusted proxy — attempt to resolve the real client IP.

	// 1. X-Forwarded-For with depth-based stripping.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := splitXFF(xff)
		if len(parts) > 0 {
			// XFF is appended left-to-right: the original client is leftmost and
			// each proxy appends its own address. With `depth` trusted proxy hops,
			// those hops added `depth` entries to the right of the real client IP.
			// The real client is therefore at index max(0, len-1-depth).
			idx := len(parts) - 1 - depth
			if idx < 0 {
				idx = 0
			}
			if ip := trimSpace(parts[idx]); ip != "" {
				return ip
			}
		}
	}

	// 2. X-Real-IP fallback (nginx and some other proxies set only this header).
	if xri := trimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}

	// 3. Fall back to the direct peer address.
	return remoteHost
}

// clientIP is the RateLimiter's internal helper; it delegates to the shared
// implementation using the limiter's configured trusted proxies and depth.
func (rl *RateLimiter) clientIP(r *http.Request) string {
	return clientIPFromRequestWithDepth(r, rl.trustedProxies, rl.proxyDepth)
}

// isTrustedProxyIP reports whether ip is contained in any of the given networks.
func isTrustedProxyIP(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// splitXFF splits a comma-separated X-Forwarded-For header value into its
// component IP strings, preserving leading/trailing spaces (callers trim).
func splitXFF(xff string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(xff); i++ {
		if xff[i] == ',' {
			parts = append(parts, xff[start:i])
			start = i + 1
		}
	}
	parts = append(parts, xff[start:])
	return parts
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
