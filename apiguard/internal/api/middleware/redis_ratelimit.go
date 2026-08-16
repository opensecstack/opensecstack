package middleware

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// slidingWindowScript implements a sorted-set sliding window rate limiter.
//
// KEYS[1]  — the rate-limit key for this client
// ARGV[1]  — limit (max requests per window)
// ARGV[2]  — window size in seconds
// ARGV[3]  — current time as Unix milliseconds
//
// Return value is a two-element array:
//
//	{1, ""}                — request allowed
//	{0, "<oldest_score>"}  — rate limit exceeded; oldest_score is the Unix-ms
//	                         timestamp of the oldest entry still in the window,
//	                         used to compute an accurate Retry-After value.
var slidingWindowScript = redis.NewScript(`
local key    = KEYS[1]
local limit  = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now    = tonumber(ARGV[3])
local window_start = now - window * 1000

-- Remove all entries that have fallen outside the current window.
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

local count = redis.call('ZCARD', key)
if count >= limit then
  -- Return the score of the oldest surviving entry so the caller can
  -- calculate exactly how many seconds until a slot opens up.
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  return {0, oldest[2]}
end

-- Add current request with a unique member to avoid collisions when two
-- requests arrive in the same millisecond.
redis.call('ZADD', key, now, now .. ':' .. math.random(1000000))
-- Keep the key alive for exactly one window; PEXPIRE handles sub-second precision.
redis.call('PEXPIRE', key, window * 1000)
return {1, ''}
`)

// RedisRateLimiter is a Redis-backed sliding-window rate limiter that
// satisfies the Limiter interface.
type RedisRateLimiter struct {
	client         *redis.Client
	rate           int
	window         int // seconds
	keyPrefix      string
	trustedProxies []*net.IPNet
	proxyDepth     int // number of XFF hops to skip (≥1)
}

// NewRedisRateLimiter constructs a RedisRateLimiter and verifies that Redis is
// reachable. It returns an error if the URL cannot be parsed or the initial
// PING fails so that NewLimiter can fall back to the in-memory implementation.
// proxyDepth controls depth-based XFF stripping; values < 1 are clamped to 1.
func NewRedisRateLimiter(redisURL, password string, db int, rate int, keyPrefix string, proxyCIDRs []string, proxyDepth int) (*RedisRateLimiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	if password != "" {
		opts.Password = password
	}
	if db != 0 {
		opts.DB = db
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close() // #nosec G104 -- best-effort close; the Ping error above is what we report
		return nil, err
	}

	if proxyDepth < 1 {
		proxyDepth = 1
	}
	return &RedisRateLimiter{
		client:         client,
		rate:           rate,
		window:         60,
		keyPrefix:      keyPrefix,
		trustedProxies: ParseTrustedProxyCIDRs(proxyCIDRs),
		proxyDepth:     proxyDepth,
	}, nil
}

// Middleware enforces the sliding-window rate limit. On limit exceeded it
// responds with HTTP 429, a JSON body, and an accurate Retry-After header
// derived from when the oldest entry in the window will expire.
// If Redis is unavailable the request is allowed (fail-open).
func (rl *RedisRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIPFromRequestWithDepth(r, rl.trustedProxies, rl.proxyDepth)
		key := rl.keyPrefix + ":" + ip
		nowMs := time.Now().UnixMilli()

		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		defer cancel()

		result, err := slidingWindowScript.Run(
			ctx, rl.client,
			[]string{key},
			rl.rate, rl.window, nowMs,
		).Slice()
		if err != nil {
			// Redis unavailable — allow the request rather than blocking all traffic.
			log.Warn().Err(err).Str("key", key).Msg("redis rate limit check failed, allowing request")
			next.ServeHTTP(w, r)
			return
		}

		// The script always returns a two-element slice: {allowed int64, payload string}.
		// If that contract is ever violated (e.g. script edited without updating this
		// handler), fail open rather than silently rate-limiting every request.
		allowed, ok := result[0].(int64)
		if !ok {
			log.Warn().Str("key", key).Interface("value", result[0]).Msg("redis rate limit script returned unexpected type, allowing request")
			next.ServeHTTP(w, r)
			return
		}
		if allowed == 1 {
			next.ServeHTTP(w, r)
			return
		}

		// Compute Retry-After from the oldest entry's score (Unix ms).
		retryAfter := rl.window // safe default: full window
		if oldestRaw, ok := result[1].(string); ok && oldestRaw != "" {
			if oldestMs, parseErr := strconv.ParseInt(oldestRaw, 10, 64); parseErr == nil {
				// The oldest entry ages out of the window at oldestMs + window*1000.
				expiresAtMs := oldestMs + int64(rl.window)*1000
				deltaMs := expiresAtMs - nowMs
				if deltaMs > 0 {
					// Round up to the nearest whole second so clients never retry too early.
					retryAfter = int(math.Ceil(float64(deltaMs) / 1000.0))
				} else {
					retryAfter = 1
				}
			}
		}

		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"error":       "Rate limit exceeded",
			"code":        "RATE_LIMITED",
			"retry_after": retryAfter,
		})
	})
}

// Stop closes the underlying Redis client and releases its resources.
func (rl *RedisRateLimiter) Stop() {
	_ = rl.client.Close()
}
