// Package cache implements a thin Redis wrapper used by ThreatFlow's hot
// lookup paths (IOC match by type+value, per-ID fetch). When the Redis URL
// is empty every method is a no-op so the server runs on any environment
// without Redis deployed — at a small performance cost.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// Cache is the concrete interface used by handlers. The no-op variant
// (returned when URL is empty) lets callers skip conditional logic at the
// call site.
type Cache struct {
	client  *redis.Client
	logger  zerolog.Logger
	ttl     time.Duration
	enabled bool

	hits   atomic.Uint64
	misses atomic.Uint64
}

// ErrMiss is returned when the key is absent. Callers typically fall through
// to the database.
var ErrMiss = errors.New("cache miss")

// Open dials Redis if url is non-empty, otherwise returns a no-op cache.
func Open(ctx context.Context, url string, ttl time.Duration, logger zerolog.Logger) (*Cache, error) {
	if url == "" {
		return &Cache{
			logger:  logger.With().Str("component", "cache").Logger(),
			ttl:     ttl,
			enabled: false,
		}, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Cache{
		client:  client,
		logger:  logger.With().Str("component", "cache").Logger(),
		ttl:     ttl,
		enabled: true,
	}, nil
}

// Enabled reports whether this cache will actually talk to Redis.
func (c *Cache) Enabled() bool { return c != nil && c.enabled }

// Close releases the underlying Redis client.
func (c *Cache) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

// Stats returns observed hit/miss counts — exposed on /health for ops insight.
func (c *Cache) Stats() (hits, misses uint64) {
	if c == nil {
		return 0, 0
	}
	return c.hits.Load(), c.misses.Load()
}

// Get fetches a JSON-encoded value into out. Returns ErrMiss when not cached
// or when the cache is disabled (so callers can treat it uniformly).
func (c *Cache) Get(ctx context.Context, key string, out any) error {
	if !c.Enabled() {
		return ErrMiss
	}
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.misses.Add(1)
			return ErrMiss
		}
		c.logger.Warn().Err(err).Str("key", key).Msg("cache get")
		c.misses.Add(1)
		return ErrMiss
	}
	if err := json.Unmarshal(data, out); err != nil {
		c.logger.Warn().Err(err).Str("key", key).Msg("cache unmarshal")
		c.misses.Add(1)
		return ErrMiss
	}
	c.hits.Add(1)
	return nil
}

// Set JSON-encodes value and stores it at key with the configured TTL.
func (c *Cache) Set(ctx context.Context, key string, value any) {
	if !c.Enabled() {
		return
	}
	data, err := json.Marshal(value)
	if err != nil {
		c.logger.Warn().Err(err).Str("key", key).Msg("cache marshal")
		return
	}
	if err := c.client.Set(ctx, key, data, c.ttl).Err(); err != nil {
		c.logger.Warn().Err(err).Str("key", key).Msg("cache set")
	}
}

// Invalidate drops one or more keys.
func (c *Cache) Invalidate(ctx context.Context, keys ...string) {
	if !c.Enabled() || len(keys) == 0 {
		return
	}
	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		c.logger.Warn().Err(err).Msg("cache del")
	}
}

// IOCMatchKey is the canonical key for the /match hot path.
func IOCMatchKey(iocType, value string) string {
	return "tf:match:" + iocType + ":" + value
}
