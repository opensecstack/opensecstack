package permifysync

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// Syncer periodically refreshes a Snapshot from Permify and persists it to
// SnapshotStore, following the same time.Ticker + context-cancellation
// shutdown shape internal/api.Server.Start uses for its HTTP server
// goroutine (the caller is expected to derive ctx from
// signal.NotifyContext, same as Server.Start does — this package does not
// install its own signal handler, so it composes cleanly with whatever else
// cmd/citadel/main.go is shutting down on the same signal).
type Syncer struct {
	fetcher  MatrixFetcher
	store    SnapshotStore
	snapshot *Snapshot
	interval time.Duration
	logger   zerolog.Logger
}

// New builds a Syncer. snapshot is the in-memory copy Gate 2 will read via
// Snapshot.Allowed — callers should hold onto the same *Snapshot passed here
// and share it with Gate 2's construction path.
func New(fetcher MatrixFetcher, store SnapshotStore, snapshot *Snapshot, interval time.Duration, logger zerolog.Logger) *Syncer {
	return &Syncer{
		fetcher:  fetcher,
		store:    store,
		snapshot: snapshot,
		interval: interval,
		logger:   logger,
	}
}

// Snapshot returns the Syncer's in-memory snapshot — the same instance
// passed to New. Convenience accessor for callers that construct the Syncer
// and want to hand the snapshot off to Gate 2 in one place.
func (s *Syncer) Snapshot() *Snapshot {
	return s.snapshot
}

// LoadInitial populates the in-memory snapshot from the persisted store,
// e.g. at startup before the first sync tick has run — so Gate 2 has
// last-known-good data (possibly empty, if nothing has synced yet) rather
// than nothing at all for the first `interval` of the process's life.
// Failure is non-fatal to the caller's judgment: it logs and leaves the
// snapshot empty, since an empty-but-honest "known=false for everything"
// snapshot is exactly what Gate 2's fallback-to-rbacMap path is designed
// to handle.
func (s *Syncer) LoadInitial(ctx context.Context) error {
	data, err := s.store.LoadSnapshot(ctx)
	if err != nil {
		s.logger.Warn().Err(err).Msg("permifysync: failed to load persisted snapshot at startup — starting from an empty snapshot")
		return err
	}
	s.snapshot.replace(data)
	s.logger.Info().Int("rows", len(data)).Msg("permifysync: loaded persisted snapshot")
	return nil
}

// Run blocks, refreshing the snapshot every interval until ctx is
// canceled. It performs one refresh immediately on start (in addition to
// LoadInitial's DB-backed load) so a fresh Permify fetch isn't delayed by
// a full interval after process start.
func (s *Syncer) Run(ctx context.Context) {
	s.refreshOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("permifysync: shutdown signal received — stopping sync loop")
			return
		case <-ticker.C:
			s.refreshOnce(ctx)
		}
	}
}

// refreshOnce performs a single fetch-and-store cycle. On fetch failure it
// logs and returns without touching the store or the in-memory snapshot —
// the existing (possibly stale, but real) snapshot is kept in both places,
// per adrs/007-permify-gate2-snapshot.md's "stale beats empty" rule for
// failures. This is distinct from a successful-but-empty fetch (the honest
// steady state today, see PermifyFetcher's doc comment), which DOES
// replace the snapshot with the fetched (empty) data.
func (s *Syncer) refreshOnce(ctx context.Context) {
	matrix, err := s.fetcher.FetchRoleActionMatrix(ctx)
	if err != nil {
		s.logger.Warn().Err(err).Msg("permifysync: fetch failed — keeping existing snapshot")
		return
	}

	if err := s.store.ReplaceSnapshot(ctx, matrix); err != nil {
		s.logger.Warn().Err(err).Msg("permifysync: failed to persist snapshot — keeping existing in-memory snapshot")
		return
	}

	s.snapshot.replace(matrix)
	s.logger.Info().Int("rows", len(matrix)).Msg("permifysync: snapshot refreshed")
}
