package middleware

// NewLimiter returns a Redis-backed Limiter when redisURL is non-empty and
// Redis is reachable; otherwise it falls back to an in-memory RateLimiter.
// keyPrefix is used only by the Redis backend to namespace keys.
// proxyDepth controls XFF depth-stripping; values < 1 are clamped to 1.
func NewLimiter(redisURL, password string, redisDB int, rate int, keyPrefix string, proxyCIDRs []string, proxyDepth int) Limiter {
	if redisURL != "" && redisURL != "redis://localhost:6379" {
		rl, err := NewRedisRateLimiter(redisURL, password, redisDB, rate, "apiguard:rl:"+keyPrefix, proxyCIDRs, proxyDepth)
		if err == nil {
			return rl
		}
		// Redis unreachable at startup — log and fall back
		// (import zerolog/log is already available via redis_ratelimit.go)
	}
	return NewRateLimiterWithProxiesAndDepth(rate, proxyCIDRs, proxyDepth)
}
