// Package correlation tracks identity claim fingerprints across sessions
// to detect the same synthetic actor submitting multiple fraudulent claims.
//
// This is Phase 4.3 sub-module 5.3. It operates independently of the
// per-session rule engine (internal/identity/scanner.go) and the ML
// service — it adds a cross-session signal on top of both.
//
// Architecture:
//   - In-memory sliding window store (v1). Future: Redis for multi-replica.
//   - Fingerprint = SHA-256(claim_type + ":" + id_number_hash + ":" + tenant).
//     Never stores raw PII — only derived fingerprints.
//   - When the same fingerprint is seen N times within the window,
//     RecordAndCheck returns isSuspicious=true.
//   - A separate "actor graph" links fingerprints that share features
//     (same email domain + same issuer_country) to detect the same
//     synthetic actor using slightly varied documents.
package correlation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Config tunes the correlator.
type Config struct {
	// Window is the sliding time window for fingerprint counts.
	// Default: 24h.
	Window time.Duration
	// Threshold is the number of matches within Window that triggers
	// a suspicious signal. Default: 3.
	Threshold int
	// GraphWindow is the sliding window for actor-graph edge linking.
	// Default: 72h.
	GraphWindow time.Duration
	// GraphThreshold is the number of linked fingerprints that triggers
	// a suspicious actor-graph signal. Default: 2.
	GraphThreshold int
	// JanitorPeriod controls how often stale entries are evicted.
	// Default: Window / 2.
	JanitorPeriod time.Duration
}

func (c *Config) setDefaults() {
	if c.Window <= 0 {
		c.Window = 24 * time.Hour
	}
	if c.Threshold <= 0 {
		c.Threshold = 3
	}
	if c.GraphWindow <= 0 {
		c.GraphWindow = 72 * time.Hour
	}
	if c.GraphThreshold <= 0 {
		c.GraphThreshold = 2
	}
	if c.JanitorPeriod <= 0 {
		c.JanitorPeriod = c.Window / 2
	}
}

// Result is the output of RecordAndCheck.
type Result struct {
	// Fingerprint is the derived key, never raw PII.
	Fingerprint string
	// Count is how many times this fingerprint was seen within Window.
	Count int
	// IsSuspicious is true when Count >= Threshold.
	IsSuspicious bool
	// ActorLinked is true when this fingerprint shares features with
	// other recent fingerprints that together exceed GraphThreshold.
	ActorLinked bool
	// LinkedCount is the number of distinct fingerprints in the actor graph.
	LinkedCount int
}

// entry tracks one fingerprint's sliding window state.
type entry struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// graphKey is a coarser feature grouping used to link related fingerprints
// without storing PII. E.g. (issuer_country, email_domain_flag).
type graphKey struct {
	issuerCountry   string
	emailDisposable bool
	claimType       string
}

// graphEntry tracks how many distinct fingerprints share a graphKey.
type graphEntry struct {
	fingerprints map[string]time.Time // fingerprint → last seen
	firstSeen    time.Time
	lastSeen     time.Time
}

// Correlator is the cross-session fingerprint tracker.
type Correlator struct {
	cfg Config
	mu  sync.Mutex

	// fingerprints: derived key → sliding window counter.
	fingerprints map[string]*entry

	// actorGraph: coarse feature key → set of linked fingerprints.
	actorGraph map[graphKey]*graphEntry

	stopJanitor chan struct{}
	once        sync.Once
}

// New returns a ready Correlator. Call Start() to begin background eviction.
func New(cfg Config) *Correlator {
	cfg.setDefaults()
	return &Correlator{
		cfg:          cfg,
		fingerprints: make(map[string]*entry),
		actorGraph:   make(map[graphKey]*graphEntry),
		stopJanitor:  make(chan struct{}),
	}
}

// Start launches the background janitor goroutine.
func (c *Correlator) Start() {
	c.once.Do(func() { go c.runJanitor() })
}

// Stop terminates the janitor.
func (c *Correlator) Stop() {
	select {
	case <-c.stopJanitor:
	default:
		close(c.stopJanitor)
	}
}

// Fingerprint derives a non-PII fingerprint from claim metadata.
// id_number is hashed before use; no raw PII touches this function's output.
func Fingerprint(claimType, idNumberHash, tenant string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", claimType, idNumberHash, tenant)))
	return "fp:" + hex.EncodeToString(h[:16]) // 128-bit prefix is sufficient
}

// RecordAndCheck records a fingerprint hit and returns the correlation result.
// ctx is reserved for future Redis integration.
func (c *Correlator) RecordAndCheck(_ context.Context, fingerprint string, gk graphKey) Result {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	// --- Fingerprint window ---
	e, ok := c.fingerprints[fingerprint]
	if !ok || now.Sub(e.firstSeen) > c.cfg.Window {
		e = &entry{count: 0, firstSeen: now, lastSeen: now}
		c.fingerprints[fingerprint] = e
	}
	e.count++
	e.lastSeen = now

	// --- Actor graph ---
	ge, ok := c.actorGraph[gk]
	if !ok || now.Sub(ge.firstSeen) > c.cfg.GraphWindow {
		ge = &graphEntry{
			fingerprints: make(map[string]time.Time),
			firstSeen:    now,
			lastSeen:     now,
		}
		c.actorGraph[gk] = ge
	}
	ge.fingerprints[fingerprint] = now
	ge.lastSeen = now

	linkedCount := len(ge.fingerprints)

	return Result{
		Fingerprint:  fingerprint,
		Count:        e.count,
		IsSuspicious: e.count >= c.cfg.Threshold,
		ActorLinked:  linkedCount >= c.cfg.GraphThreshold,
		LinkedCount:  linkedCount,
	}
}

// Count returns the current hit count for a fingerprint (test helper).
func (c *Correlator) Count(fingerprint string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.fingerprints[fingerprint]; ok {
		return e.count
	}
	return 0
}

func (c *Correlator) runJanitor() {
	t := time.NewTicker(c.cfg.JanitorPeriod)
	defer t.Stop()
	for {
		select {
		case <-c.stopJanitor:
			return
		case <-t.C:
			c.evict(time.Now())
		}
	}
}

func (c *Correlator) evict(now time.Time) {
	fpCutoff := now.Add(-2 * c.cfg.Window)
	gkCutoff := now.Add(-2 * c.cfg.GraphWindow)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.fingerprints {
		if e.lastSeen.Before(fpCutoff) {
			delete(c.fingerprints, k)
		}
	}
	for gk, ge := range c.actorGraph {
		// Evict stale fingerprint entries within the graph entry.
		for fp, ts := range ge.fingerprints {
			if ts.Before(gkCutoff) {
				delete(ge.fingerprints, fp)
			}
		}
		// Remove the graph entry when all fingerprints are evicted or
		// when the entry itself has not been touched since 2× the graph window.
		// Using lastSeen (rather than firstSeen) mirrors the fingerprint eviction
		// policy and correctly handles long-lived graph entries that stay active.
		if len(ge.fingerprints) == 0 || ge.lastSeen.Before(gkCutoff) {
			delete(c.actorGraph, gk)
		}
	}
}
