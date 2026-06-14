package citadel

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/metrics"
)

// MitigationRecord is the minimum view of a mitigation row needed to
// produce an `openscrub.mitigation` event. Mirrors db.Mitigation but
// kept here so this package doesn't import db.
type MitigationRecord struct {
	ID             uuid.UUID
	RuleID         uuid.UUID
	StartedAt      time.Time
	EndedAt        time.Time
	PacketsDropped int64
	BytesDropped   int64
	SrcIP          string
	Rule           RuleSummary
}

// MitigationStore is the persistence interface the watcher needs. It
// drives a (pending → sent | failed) state machine on the row so we
// never flag `sent` until CITADEL has durably acknowledged the event.
type MitigationStore interface {
	PendingForEmit(ctx context.Context, minDuration time.Duration, limit int) ([]MitigationRecord, error)
	// MarkSending records that an emit attempt is in flight and binds
	// the persisted row to the in-flight envelope id. Increments the
	// row's `attempts` counter.
	MarkSending(ctx context.Context, mitigationID uuid.UUID, eventID string) error
	// MarkSent flips the row to state='sent' on confirmed CITADEL 2xx.
	MarkSent(ctx context.Context, mitigationID uuid.UUID) error
	// MarkFailed flips the row to state='failed' after the retry queue
	// gives up (max retries OR buffer overflow eviction). The row is
	// preserved for ops triage; an admin endpoint re-queues or buries
	// it.
	MarkFailed(ctx context.Context, mitigationID uuid.UUID, lastError string) error
	// LookupByEventID resolves a delivery confirmation back to the
	// originating mitigation row. Returns uuid.Nil when unknown
	// (event was a rule_change, or the binding was lost across a
	// process restart — those are reconciled by the next tick).
	LookupByEventID(ctx context.Context, eventID string) (uuid.UUID, error)
	// MarkEmitted is retained for backward compatibility with callers
	// that read the legacy boolean column. Implementations should
	// route to MarkSent.
	//
	// Deprecated: scheduled for removal in v1.1.0 alongside the
	// `mitigations.emitted` column. New code MUST use MarkSent /
	// MarkFailed directly. See db/mitigation_store.go for the matching
	// note and the migration 0003 plan.
	MarkEmitted(ctx context.Context, id uuid.UUID) error
}

// Watcher periodically scans for mitigations that have ended, lasted
// at least MinDuration (default 5s), and whose state is still 'pending'.
// It emits one event per row. The row only transitions to 'sent' once
// CITADEL has confirmed delivery — either synchronously (Submit returns
// SubmitDelivered) or asynchronously via Client.Confirmations() after a
// queued retry succeeded.
type Watcher struct {
	client      *Client
	store       MitigationStore
	minDuration time.Duration
	tickEvery   time.Duration
	nodeName    string
	logger      zerolog.Logger

	// In-flight bookkeeping for queued events. Lets the confirmation
	// drainer find the originating mitigation id without re-reading
	// the DB. Survives best-effort across normal operation; on process
	// crash, the next Tick re-emits because state is still 'pending'.
	mu       sync.Mutex
	inFlight map[string]uuid.UUID // event_id -> mitigation_id
}

// WatcherConfig carries Watcher tunables.
type WatcherConfig struct {
	MinDuration time.Duration
	TickEvery   time.Duration
	NodeName    string
}

// NewWatcher builds a Watcher.
func NewWatcher(c *Client, store MitigationStore, cfg WatcherConfig, logger zerolog.Logger) *Watcher {
	if cfg.MinDuration <= 0 {
		cfg.MinDuration = 5 * time.Second
	}
	if cfg.TickEvery <= 0 {
		cfg.TickEvery = 10 * time.Second
	}
	return &Watcher{
		client:      c,
		store:       store,
		minDuration: cfg.MinDuration,
		tickEvery:   cfg.TickEvery,
		nodeName:    cfg.NodeName,
		logger:      logger.With().Str("component", "citadel-watcher").Logger(),
		inFlight:   make(map[string]uuid.UUID),
	}
}

// Run blocks until ctx is cancelled, calling Tick at every interval.
// Also drains the CITADEL client's delivery-confirmation channel so
// asynchronously-acknowledged events flip the persisted state machine.
func (w *Watcher) Run(ctx context.Context) {
	if w.store == nil {
		w.logger.Warn().Msg("mitigation store nil — watcher disabled")
		return
	}
	go w.drainConfirmations(ctx)

	t := time.NewTicker(w.tickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.Tick(ctx); err != nil {
				w.logger.Warn().Err(err).Msg("watcher tick failed")
			}
		}
	}
}

// drainConfirmations watches the CITADEL retry loop's delivery channel
// and applies the result to the persisted state. It also handles the
// case where the watcher has lost its in-memory binding (process
// restart): we fall back to MitigationStore.LookupByEventID so a fresh
// process can still finish the conversation.
func (w *Watcher) drainConfirmations(ctx context.Context) {
	if w.client == nil {
		return
	}
	ch := w.client.Confirmations()
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-ch:
			w.applyConfirmation(ctx, d)
		}
	}
}

func (w *Watcher) applyConfirmation(ctx context.Context, d DeliveryConfirmation) {
	w.mu.Lock()
	mitID, ok := w.inFlight[d.EventID]
	if ok {
		delete(w.inFlight, d.EventID)
	}
	w.mu.Unlock()

	if !ok && d.EventID != "" {
		// Try the persisted lookup so a watcher restart still settles
		// the row.
		if id, err := w.store.LookupByEventID(ctx, d.EventID); err == nil && id != uuid.Nil {
			mitID = id
			ok = true
		}
	}
	if !ok {
		// Confirmation belongs to a non-mitigation event (e.g.
		// rule_change) or to a row owned by a previous incarnation
		// that's already been re-emitted. Bump the metric and move on.
		if d.Delivered {
			metrics.CitadelEmitTotal.WithLabelValues("delivered").Inc()
		} else {
			metrics.CitadelEmitTotal.WithLabelValues("failed").Inc()
		}
		return
	}

	if d.Delivered {
		if err := w.store.MarkSent(ctx, mitID); err != nil {
			w.logger.Warn().Err(err).Str("mitigation_id", mitID.String()).
				Msg("could not mark mitigation sent")
		}
		metrics.CitadelEmitTotal.WithLabelValues("delivered").Inc()
		return
	}

	reason := "max retries exhausted"
	if d.Err != nil {
		reason = d.Err.Error()
	}
	if err := w.store.MarkFailed(ctx, mitID, reason); err != nil {
		w.logger.Warn().Err(err).Str("mitigation_id", mitID.String()).
			Msg("could not mark mitigation failed")
	}
	metrics.CitadelEmitTotal.WithLabelValues("failed").Inc()
}

// Tick performs one sweep. Public so unit tests can drive it directly.
//
// Contract:
//   * SubmitDelivered  → MarkSent immediately (durable receipt).
//   * SubmitDryRun     → MarkSent (no real CITADEL endpoint to wait on).
//   * SubmitQueued     → leave row 'pending' + record in_flight binding;
//                        the confirmation drainer flips state on the
//                        async outcome.
//   * SubmitDropped    → MarkFailed immediately; ops surface metric.
//   * permanent error  → MarkFailed; row remains for triage.
func (w *Watcher) Tick(ctx context.Context) error {
	pending, err := w.store.PendingForEmit(ctx, w.minDuration, 100)
	if err != nil {
		return err
	}
	for _, m := range pending {
		ev := MitigationEvent{
			EventEnvelope: NewEnvelope("openscrub.mitigation", w.nodeName),
			Rule:          m.Rule,
			SrcIP:         m.SrcIP,
			Action:        actionFor(m.Rule.Type),
			Packets:       m.PacketsDropped,
			Bytes:         m.BytesDropped,
			WindowSeconds: int(m.EndedAt.Sub(m.StartedAt).Seconds()),
		}
		if err := w.store.MarkSending(ctx, m.ID, ev.ID); err != nil {
			w.logger.Warn().Err(err).Str("mitigation_id", m.ID.String()).
				Msg("could not bind mitigation to event id (will retry next tick)")
			continue
		}
		w.mu.Lock()
		w.inFlight[ev.ID] = m.ID
		w.mu.Unlock()

		outcome, submitErr := w.client.Submit(ctx, ev)
		switch outcome {
		case SubmitDelivered, SubmitDryRun:
			if submitErr != nil {
				// Permanent error (e.g. 4xx). Do not mark sent — flip
				// to failed so ops can re-queue or bury.
				w.mu.Lock()
				delete(w.inFlight, ev.ID)
				w.mu.Unlock()
				_ = w.store.MarkFailed(ctx, m.ID, submitErr.Error())
				metrics.CitadelEmitTotal.WithLabelValues("failed").Inc()
				w.logger.Warn().Err(submitErr).Str("mitigation_id", m.ID.String()).
					Msg("citadel mitigation emit permanent failure")
				continue
			}
			w.mu.Lock()
			delete(w.inFlight, ev.ID)
			w.mu.Unlock()
			if err := w.store.MarkSent(ctx, m.ID); err != nil {
				w.logger.Warn().Err(err).Str("mitigation_id", m.ID.String()).
					Msg("could not mark mitigation sent")
			}
			metrics.CitadelEmitTotal.WithLabelValues("delivered").Inc()

		case SubmitQueued:
			// Leave row 'pending'. The confirmation drainer flips it
			// when the async retry succeeds or finally fails.
			metrics.CitadelEmitTotal.WithLabelValues("queued").Inc()

		case SubmitDropped:
			w.mu.Lock()
			delete(w.inFlight, ev.ID)
			w.mu.Unlock()
			reason := "buffer overflow"
			if submitErr != nil {
				reason = submitErr.Error()
			}
			_ = w.store.MarkFailed(ctx, m.ID, reason)
			metrics.CitadelEmitTotal.WithLabelValues("dropped").Inc()
			w.logger.Error().Str("mitigation_id", m.ID.String()).
				Msg("citadel retry buffer full — mitigation marked failed")
		}
	}
	return nil
}

func actionFor(ruleType string) string {
	if ruleType == "ratelimit" {
		return "ratelimit"
	}
	return "drop"
}
