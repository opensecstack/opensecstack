// Package denylist implements JWT revocation for VertGuard.
//
// Operators revoke either an individual token (Kind=KindJTI) or every
// token issued for a subject (Kind=KindSub). The Cache holds an in-
// memory snapshot refreshed periodically from a Store, so the auth hot
// path never blocks on the database.
package denylist

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/auth"
)

// Kind constants.
const (
	KindJTI = "jti"
	KindSub = "sub"
)

// DefaultRefreshInterval is the cache refresh cadence used when the
// caller doesn't override it.
const DefaultRefreshInterval = 30 * time.Second

// Entry is one denylist row.
type Entry struct {
	ID        uuid.UUID  `json:"id"`
	Kind      string     `json:"kind"`
	Value     string     `json:"value"`
	Reason    string     `json:"reason,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`
	RevokedAt time.Time  `json:"revoked_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IsActive reports whether the entry should still block tokens at t.
func (e Entry) IsActive(t time.Time) bool {
	if e.ExpiresAt == nil {
		return true
	}
	return t.Before(*e.ExpiresAt)
}

// Store is the persistence contract. Production uses pgx; tests use the
// in-memory backend in this package.
type Store interface {
	List(ctx context.Context) ([]Entry, error)
	Add(ctx context.Context, e Entry) error
	Remove(ctx context.Context, kind, value string) error
}

// MetricsHook is the optional metrics surface; kept narrow so this
// package doesn't depend on the metrics package directly.
type MetricsHook interface {
	SetDenylistSize(n int)
	IncDenylistHit(kind string)
}

// snapshot is what IsRevoked actually reads. Map values carry the
// reason so the auth middleware can include it in the 401 body.
type snapshot struct {
	entries map[string]Entry
	loaded  time.Time
}

// Cache wraps a Store with an atomically-swapped in-memory snapshot.
type Cache struct {
	store    Store
	logger   *zerolog.Logger
	metrics  MetricsHook
	interval time.Duration

	now func() time.Time

	snap atomic.Pointer[snapshot]

	tickerMu sync.Mutex
	ticker   *time.Ticker
	stop     chan struct{}
	stopped  atomic.Bool
}

// Option configures a Cache.
type Option func(*Cache)

// WithRefreshInterval overrides the default 30s ticker.
func WithRefreshInterval(d time.Duration) Option {
	return func(c *Cache) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithLogger sets the zerolog logger.
func WithLogger(l *zerolog.Logger) Option {
	return func(c *Cache) { c.logger = l }
}

// WithMetrics wires the metrics hook.
func WithMetrics(m MetricsHook) Option {
	return func(c *Cache) { c.metrics = m }
}

// withClock is exported only via tests.
func withClock(now func() time.Time) Option {
	return func(c *Cache) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCache builds a Cache with an empty initial snapshot. Call Refresh
// before serving traffic to populate it.
func NewCache(s Store, opts ...Option) *Cache {
	c := &Cache{
		store:    s,
		interval: DefaultRefreshInterval,
		now:      time.Now,
		stop:     make(chan struct{}),
	}
	for _, o := range opts {
		o(c)
	}
	empty := &snapshot{entries: map[string]Entry{}, loaded: time.Time{}}
	c.snap.Store(empty)
	return c
}

// Refresh reloads the snapshot from the underlying Store. On error, the
// existing snapshot is kept so a transient DB hiccup doesn't open a
// revocation gap.
func (c *Cache) Refresh(ctx context.Context) error {
	if c == nil || c.store == nil {
		return errors.New("denylist: nil cache or store")
	}
	entries, err := c.store.List(ctx)
	if err != nil {
		return err
	}
	now := c.now()
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		if !e.IsActive(now) {
			continue
		}
		m[key(e.Kind, e.Value)] = e
	}
	c.snap.Store(&snapshot{entries: m, loaded: now})
	if c.metrics != nil {
		c.metrics.SetDenylistSize(len(m))
	}
	return nil
}

// IsRevoked reports whether the claims have been revoked. Returns the
// reason from the matching entry so the caller can surface it.
func (c *Cache) IsRevoked(claims *auth.Claims) (bool, string) {
	if c == nil || claims == nil {
		return false, ""
	}
	snap := c.snap.Load()
	if snap == nil || len(snap.entries) == 0 {
		return false, ""
	}
	now := c.now()
	if claims.Jti != "" {
		if e, ok := snap.entries[key(KindJTI, claims.Jti)]; ok && e.IsActive(now) {
			if c.metrics != nil {
				c.metrics.IncDenylistHit(KindJTI)
			}
			return true, e.Reason
		}
	}
	if claims.Sub != "" {
		if e, ok := snap.entries[key(KindSub, claims.Sub)]; ok && e.IsActive(now) {
			if c.metrics != nil {
				c.metrics.IncDenylistHit(KindSub)
			}
			return true, e.Reason
		}
	}
	return false, ""
}

// Size returns the current snapshot size — useful for tests + metrics.
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}
	snap := c.snap.Load()
	if snap == nil {
		return 0
	}
	return len(snap.entries)
}

// Run drives the refresh ticker until ctx is cancelled or Close is
// called. Safe to invoke once per Cache.
func (c *Cache) Run(ctx context.Context) {
	if c == nil {
		return
	}
	c.tickerMu.Lock()
	if c.ticker != nil {
		c.tickerMu.Unlock()
		return
	}
	c.ticker = time.NewTicker(c.interval)
	t := c.ticker
	c.tickerMu.Unlock()

	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-t.C:
			if err := c.Refresh(ctx); err != nil && c.logger != nil {
				c.logger.Warn().Err(err).Msg("denylist refresh failed; keeping previous snapshot")
			}
		}
	}
}

// Close stops the ticker. Safe to call multiple times.
func (c *Cache) Close() {
	if c == nil {
		return
	}
	if c.stopped.Swap(true) {
		return
	}
	close(c.stop)
}

func key(kind, value string) string { return kind + ":" + value }
