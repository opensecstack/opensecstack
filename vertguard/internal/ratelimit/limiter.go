// Package ratelimit provides per-key token-bucket rate limiting for
// HTTP middleware. Keys are pluggable: client IP for anonymous
// traffic, JWT subject for authenticated traffic.
//
// Buckets are kept in memory. A janitor goroutine sweeps idle entries
// every `cleanupInterval` to bound memory under high cardinality.
//
// Per-key overrides (see overrides.go) ride on top of the global Config:
// when a request key matches an override, the bucket is constructed
// with the override's RPS+burst instead. The snapshot is swapped
// atomically so admin updates are lock-free on the hot path.
package ratelimit

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"

	"github.com/opensecstack/vertguard/internal/auth"
)

// Config tunes a Limiter.
type Config struct {
	RPS             float64       // sustained requests per second per key
	Burst           int           // burst above sustained rate
	CleanupInterval time.Duration // idle bucket sweep interval (default 5m)
	IdleTTL         time.Duration // bucket eviction threshold (default 10m)
}

type bucket struct {
	lim        *rate.Limiter
	seen       time.Time
	overridden bool // tracks whether the bucket was built from an override
}

// OverrideHook is the optional metrics surface fired whenever an
// override-derived bucket processes a request. Kept narrow so the
// metrics package import doesn't leak into ratelimit.
type OverrideHook interface {
	IncOverrideHit(kind, decision string)
	SetActiveOverrides(n int)
}

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg     Config
	mu      sync.Mutex
	buckets map[string]*bucket
	stop    chan struct{}

	// overrides snapshot keyed by "kind:value". Atomic swap keeps Allow
	// lock-free on lookup. A nil map is the same as no overrides loaded.
	overrides atomic.Pointer[map[string]Override]

	hook OverrideHook
}

// New starts a janitor goroutine. Call Stop to release it.
func New(cfg Config) *Limiter {
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 10 * time.Minute
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.RPS) + 1
	}
	l := &Limiter{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
	}
	empty := map[string]Override{}
	l.overrides.Store(&empty)
	go l.janitor()
	return l
}

// SetOverrideHook wires a metrics hook. Optional; nil is fine.
func (l *Limiter) SetOverrideHook(h OverrideHook) {
	l.hook = h
	if h != nil {
		if snap := l.overrides.Load(); snap != nil {
			h.SetActiveOverrides(len(*snap))
		}
	}
}

// SetOverrides atomically swaps the active override snapshot.
//
// LIMITATION: existing buckets keep the rate they were created with.
// When an override changes (or is removed) for a key whose bucket is
// still in memory, that bucket continues at the old rate until it is
// evicted by the janitor (IdleTTL). Operators who need precise
// cut-over can hard-rotate by removing+re-adding under a different
// value, or wait one IdleTTL window. We deliberately do not rebuild
// active buckets here — it adds locking complexity for marginal gain
// at this stage.
func (l *Limiter) SetOverrides(overrides []Override) {
	m := make(map[string]Override, len(overrides))
	for _, o := range overrides {
		if o.Kind == "" || o.Value == "" {
			continue
		}
		m[o.Kind+":"+o.Value] = o
	}
	l.overrides.Store(&m)
	if l.hook != nil {
		l.hook.SetActiveOverrides(len(m))
	}
}

// Refresh pulls the override list from the store and swaps it in.
func (l *Limiter) Refresh(ctx context.Context, store OverrideStore) error {
	if l == nil || store == nil {
		return nil
	}
	list, err := store.List(ctx)
	if err != nil {
		return err
	}
	l.SetOverrides(list)
	return nil
}

// RunRefresh drives the refresh ticker until ctx is cancelled or Stop
// is called. Errors are swallowed (logged via the optional logger) so
// a transient DB hiccup doesn't take down the limiter.
func (l *Limiter) RunRefresh(ctx context.Context, store OverrideStore, interval time.Duration, logger *zerolog.Logger) {
	if l == nil || store == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	// Prime the snapshot before entering the loop so the first request
	// after startup already sees the configured overrides.
	if err := l.Refresh(ctx, store); err != nil && logger != nil {
		logger.Warn().Err(err).Msg("ratelimit override refresh failed; continuing with empty snapshot")
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stop:
			return
		case <-t.C:
			if err := l.Refresh(ctx, store); err != nil && logger != nil {
				logger.Warn().Err(err).Msg("ratelimit override refresh failed; keeping previous snapshot")
			}
		}
	}
}

// lookupOverride checks the atomic snapshot for the given key.
func (l *Limiter) lookupOverride(key string) (Override, bool) {
	snap := l.overrides.Load()
	if snap == nil || len(*snap) == 0 {
		return Override{}, false
	}
	o, ok := (*snap)[key]
	if !ok {
		return Override{}, false
	}
	if !o.IsActive(time.Now()) {
		return Override{}, false
	}
	return o, true
}

// Allow consumes one token. Returns false when the bucket is empty.
func (l *Limiter) Allow(key string) bool {
	override, hasOverride := l.lookupOverride(key)

	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		rps := l.cfg.RPS
		burst := l.cfg.Burst
		if hasOverride {
			rps = override.RPS
			burst = override.Burst
		}
		// Burst=0 is a legitimate "block this key entirely" override —
		// rate.NewLimiter accepts zero and Allow returns false on every
		// call. RPS=0 with non-zero burst gives a finite quota then a
		// hard stop until cleared.
		b = &bucket{
			lim:        rate.NewLimiter(rate.Limit(rps), burst),
			seen:       time.Now(),
			overridden: hasOverride,
		}
		l.buckets[key] = b
	}
	b.seen = time.Now()
	overridden := b.overridden
	l.mu.Unlock()

	allowed := b.lim.Allow()
	if overridden && l.hook != nil {
		decision := "allowed"
		if !allowed {
			decision = "limited"
		}
		// Override-bucket key is "kind:value" — split off the kind for
		// the metric label, preserving cardinality of the global metric.
		kind := ""
		if i := strings.IndexByte(key, ':'); i > 0 {
			kind = key[:i]
		}
		l.hook.IncOverrideHit(kind, decision)
	}
	return allowed
}

// Stop halts the janitor. Idempotent.
func (l *Limiter) Stop() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
}

func (l *Limiter) janitor() {
	t := time.NewTicker(l.cfg.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			l.mu.Lock()
			for k, b := range l.buckets {
				if now.Sub(b.seen) > l.cfg.IdleTTL {
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Metrics is the subset of vertguard's registry the middleware uses.
type Metrics interface {
	IncRateLimited(scope string)
}

// Middleware returns a chi-compatible middleware that rejects with
// 429 when the per-key bucket is empty. The key is the JWT subject
// when authenticated, else the client IP from chi/middleware.RealIP.
func Middleware(l *Limiter, m Metrics, logger *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, scope := keyFor(r)
			if !l.Allow(key) {
				if m != nil {
					m.IncRateLimited(scope)
				}
				if logger != nil {
					logger.Warn().
						Str("key", key).
						Str("scope", scope).
						Str("path", r.URL.Path).
						Msg("rate limit exceeded")
				}
				w.Header().Set("Retry-After", "1")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded","code":"rate_limited"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func keyFor(r *http.Request) (string, string) {
	if claims, ok := auth.ClaimsFromContext(r.Context()); ok && claims.Sub != "" {
		return "sub:" + claims.Sub, "subject"
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	return "ip:" + ip, "ip"
}
