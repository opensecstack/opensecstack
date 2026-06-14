package feed

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/stix"
)

// Scheduler polls enabled feeds from the database on their configured interval
// and imports each resulting STIX bundle via stix.Importer. It is safe to
// start once per process; subsequent calls to Start are no-ops.
type Scheduler struct {
	feeds    *store.FeedStore
	importer *stix.Importer
	logger   zerolog.Logger

	tick time.Duration

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewScheduler wires a Scheduler to the feed store + importer.
func NewScheduler(feeds *store.FeedStore, importer *stix.Importer, logger zerolog.Logger) *Scheduler {
	return &Scheduler{
		feeds:    feeds,
		importer: importer,
		logger:   logger.With().Str("component", "scheduler").Logger(),
		tick:     1 * time.Minute,
	}
}

// WithTick overrides the scan interval. Defaults to 1 minute; tests use 100ms.
func (s *Scheduler) WithTick(d time.Duration) *Scheduler {
	s.tick = d
	return s
}

// Start launches the scheduler loop. Non-blocking; call Stop to shut down.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	s.mu.Unlock()

	go s.loop(loopCtx)
	s.logger.Info().Dur("tick", s.tick).Msg("feed scheduler started")
}

// Stop signals the loop to exit and waits for it.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.cancel()
	done := s.done
	s.started = false
	s.mu.Unlock()
	<-done
	s.logger.Info().Msg("feed scheduler stopped")
}

func (s *Scheduler) loop(ctx context.Context) {
	defer close(s.done)
	// Run a scan immediately so the first feed does not wait a full tick.
	s.scan(ctx)

	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scan(ctx)
		}
	}
}

// scan polls every enabled feed whose next-poll time has elapsed.
func (s *Scheduler) scan(ctx context.Context) {
	feeds, err := s.feeds.List(ctx, true)
	if err != nil {
		s.logger.Error().Err(err).Msg("list feeds")
		return
	}
	for _, f := range feeds {
		if !dueForPoll(f) {
			continue
		}
		s.pollOne(ctx, f)
	}
}

// pollOne runs a single feed end-to-end, recording success or failure on the
// feeds row.
func (s *Scheduler) pollOne(ctx context.Context, f *store.Feed) {
	logger := s.logger.With().Str("feed", f.Name).Str("kind", f.FeedType).Logger()
	poller, err := buildPoller(f)
	if err != nil {
		logger.Error().Err(err).Msg("build poller")
		_ = s.feeds.RecordPoll(ctx, f.ID, 0, false)
		return
	}

	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	payload, count, err := poller.Poll(pollCtx)
	if err != nil {
		logger.Warn().Err(err).Msg("poll failed")
		_ = s.feeds.RecordPoll(ctx, f.ID, 0, false)
		return
	}
	if count == 0 {
		logger.Info().Msg("poll ok — no new indicators")
		_ = s.feeds.RecordPoll(ctx, f.ID, 0, true)
		return
	}

	feedID := f.ID
	res, err := s.importer.Import(ctx, payload, f.Name, &feedID)
	if err != nil {
		logger.Error().Err(err).Msg("import failed")
		_ = s.feeds.RecordPoll(ctx, f.ID, 0, false)
		return
	}
	logger.Info().
		Int("indicators_seen", res.IndicatorsSeen).
		Int("iocs_upserted", res.IOCsUpserted).
		Int("skipped", res.Skipped).
		Msg("poll imported")
	_ = s.feeds.RecordPoll(ctx, f.ID, res.IOCsUpserted, true)
}

// buildPoller constructs the right Poller for this feed row.
func buildPoller(f *store.Feed) (Poller, error) {
	cfg := Config{
		Name:           f.Name,
		URL:            f.URL,
		ConfidenceBase: f.ConfidenceBase,
	}
	switch f.FeedType {
	case "taxii21":
		return NewTAXII(cfg), nil
	case "csv":
		return NewCSV(cfg), nil
	case "misp":
		return NewMISP(cfg), nil
	case "opencti":
		return NewOpenCTI(cfg), nil
	case "manual":
		return nil, fmt.Errorf("manual feed %q has no poller", f.Name)
	}
	return nil, fmt.Errorf("unknown feed type %q", f.FeedType)
}

// dueForPoll decides whether a feed should run this tick. last_poll_at + the
// poll_interval must be in the past. Never-polled feeds are always due.
func dueForPoll(f *store.Feed) bool {
	if f.LastPollAt == nil {
		return true
	}
	interval, err := parsePostgresInterval(f.PollInterval)
	if err != nil {
		return true // be permissive on parse failures — better a poll than silence
	}
	return time.Since(*f.LastPollAt) >= interval
}

// parsePostgresInterval accepts the textual postgres interval form
// (e.g. "01:00:00" or "1 hour 30 mins"). Enough precision for scheduler needs.
func parsePostgresInterval(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Hour, nil
	}
	// HH:MM:SS form
	if strings.Count(s, ":") == 2 {
		var h, m, sec int
		if _, err := fmt.Sscanf(s, "%d:%d:%d", &h, &m, &sec); err == nil {
			return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second, nil
		}
	}
	// "1 hour", "30 mins", "2 days" forms — naive tokeniser
	tokens := strings.Fields(s)
	var total time.Duration
	for i := 0; i+1 < len(tokens); i += 2 {
		var n int
		if _, err := fmt.Sscanf(tokens[i], "%d", &n); err != nil {
			continue
		}
		unit := strings.ToLower(strings.TrimSuffix(tokens[i+1], "s"))
		switch unit {
		case "second", "sec":
			total += time.Duration(n) * time.Second
		case "minute", "min":
			total += time.Duration(n) * time.Minute
		case "hour", "hr":
			total += time.Duration(n) * time.Hour
		case "day":
			total += time.Duration(n) * 24 * time.Hour
		}
	}
	if total == 0 {
		return time.Hour, nil
	}
	return total, nil
}

// Ensure uuid is referenced so unused-import lint never trips if we remove the
// feedID pointer path above.
var _ = uuid.Nil
