package atlas

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// DefaultSourceURL is MITRE ATLAS upstream YAML. Operators can override
// at process boot via the VERTGUARD_ATLAS_SOURCE_URL environment
// variable, or programmatically via SyncerConfig.SourceURL /
// config.Threatfeed.AtlasSourceURL.
const DefaultSourceURL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

// SourceURLEnv is the environment variable consulted when
// SyncerConfig.SourceURL is empty. Lets ops point at an internal mirror
// without rebuilding the binary.
const SourceURLEnv = "VERTGUARD_ATLAS_SOURCE_URL"

// Metrics is the subset of vertguard's registry the syncer touches.
type Metrics interface {
	SetThreatFeedStaleness(source string, seconds float64)
	SetThreatFeedIOCs(source, atlasTechnique string, n float64)
}

// SyncerConfig tunes the syncer.
type SyncerConfig struct {
	SourceURL    string
	HTTPTimeout  time.Duration
	SyncInterval time.Duration
}

// Syncer maintains an in-memory ATLAS technique cache, refreshed
// periodically from a remote YAML source. Falls back to the
// embedded `Initial()` set when sync has never succeeded.
type Syncer struct {
	cfg     SyncerConfig
	http    *http.Client
	logger  zerolog.Logger
	metrics Metrics

	mu           sync.RWMutex
	cache        map[string]Technique
	lastSyncedAt atomic.Int64 // unix seconds
}

// Report summarises a single sync cycle.
type Report struct {
	Added     int
	Updated   int
	Removed   int
	Unchanged int
	Duration  time.Duration
}

// NewSyncer returns a syncer seeded with the embedded Initial() set
// so callers always observe a non-empty cache.
func NewSyncer(cfg SyncerConfig, logger zerolog.Logger, metrics Metrics) *Syncer {
	if cfg.SourceURL == "" {
		if v := os.Getenv(SourceURLEnv); v != "" {
			cfg.SourceURL = v
		} else {
			cfg.SourceURL = DefaultSourceURL
		}
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 24 * time.Hour
	}

	s := &Syncer{
		cfg:     cfg,
		http:    &http.Client{Timeout: cfg.HTTPTimeout},
		logger:  logger.With().Str("component", "atlas_sync").Logger(),
		metrics: metrics,
	}
	seed := Initial()
	m := make(map[string]Technique, len(seed))
	for _, t := range seed {
		m[t.ID] = t
	}
	s.cache = m
	return s
}

// Get returns the technique with the given ID. Falls through to the
// fallback set if the cache lookup misses.
func (s *Syncer) Get(id string) (Technique, bool) {
	s.mu.RLock()
	t, ok := s.cache[id]
	s.mu.RUnlock()
	return t, ok
}

// All returns a copy of the current technique cache.
func (s *Syncer) All() []Technique {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Technique, 0, len(s.cache))
	for _, t := range s.cache {
		out = append(out, t)
	}
	return out
}

// LastSyncedAt returns the unix timestamp of the most recent
// successful sync, or 0 if never synced.
func (s *Syncer) LastSyncedAt() int64 { return s.lastSyncedAt.Load() }

// Sync fetches the upstream YAML and atomically swaps the cache.
func (s *Syncer) Sync(ctx context.Context) (Report, error) {
	start := time.Now()
	rep := Report{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.SourceURL, nil)
	if err != nil {
		return rep, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return rep, fmt.Errorf("fetch atlas: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rep, fmt.Errorf("atlas HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024)) // 32 MiB cap
	if err != nil {
		return rep, fmt.Errorf("read atlas: %w", err)
	}

	techniques, err := parseYAML(body)
	if err != nil {
		return rep, fmt.Errorf("parse atlas: %w", err)
	}
	if len(techniques) == 0 {
		return rep, fmt.Errorf("atlas: zero techniques parsed (schema drift?)")
	}

	newCache := make(map[string]Technique, len(techniques))
	for _, t := range techniques {
		newCache[t.ID] = t
	}

	s.mu.Lock()
	old := s.cache
	for id, t := range newCache {
		if existing, ok := old[id]; !ok {
			rep.Added++
		} else if existing != t {
			rep.Updated++
		} else {
			rep.Unchanged++
		}
	}
	for id := range old {
		if _, ok := newCache[id]; !ok {
			rep.Removed++
		}
	}
	s.cache = newCache
	s.mu.Unlock()

	rep.Duration = time.Since(start)
	s.lastSyncedAt.Store(time.Now().Unix())

	if s.metrics != nil {
		s.metrics.SetThreatFeedStaleness("atlas", 0)
	}
	s.logger.Info().
		Int("added", rep.Added).
		Int("updated", rep.Updated).
		Int("removed", rep.Removed).
		Int("unchanged", rep.Unchanged).
		Dur("duration", rep.Duration).
		Msg("atlas sync complete")
	return rep, nil
}

// RunPeriodic loops Sync until ctx is cancelled. Errors are logged
// but never abort the loop.
func (s *Syncer) RunPeriodic(ctx context.Context) {
	t := time.NewTicker(s.cfg.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ctxSync, cancel := context.WithTimeout(ctx, s.cfg.HTTPTimeout)
			if _, err := s.Sync(ctxSync); err != nil {
				s.logger.Warn().Err(err).Msg("atlas periodic sync failed")
			}
			cancel()
			if s.metrics != nil {
				if last := s.lastSyncedAt.Load(); last > 0 {
					s.metrics.SetThreatFeedStaleness("atlas", float64(time.Now().Unix()-last))
				}
			}
		}
	}
}

// ─── YAML parsing ──────────────────────────────────────────────────

type yamlRoot struct {
	Matrices []struct {
		ID         string          `yaml:"id"`
		Tactics    []yamlTactic    `yaml:"tactics"`
		Techniques []yamlTechnique `yaml:"techniques"`
	} `yaml:"matrices"`
}

type yamlTactic struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

type yamlTechnique struct {
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	Tactics        []string `yaml:"tactics"`
	SubtechniqueOf string   `yaml:"subtechnique-of"`
}

func parseYAML(body []byte) ([]Technique, error) {
	var root yamlRoot
	if err := yaml.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	if len(root.Matrices) == 0 {
		return nil, fmt.Errorf("no matrices in YAML")
	}
	mx := root.Matrices[0]
	tacticByID := make(map[string]string, len(mx.Tactics))
	for _, t := range mx.Tactics {
		tacticByID[t.ID] = t.Name
	}

	out := make([]Technique, 0, len(mx.Techniques))
	for _, yt := range mx.Techniques {
		t := Technique{
			ID:          yt.ID,
			Name:        yt.Name,
			Description: yt.Description,
			URL:         "https://atlas.mitre.org/techniques/" + yt.ID,
		}
		if len(yt.Tactics) > 0 {
			t.TacticID = yt.Tactics[0]
			t.TacticName = tacticByID[yt.Tactics[0]]
		}
		out = append(out, t)
	}
	return out, nil
}
