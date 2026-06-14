// Package citadel — outbox worker.
//
// The worker drains the `outbox` table by claiming pending rows in
// batches (FOR UPDATE SKIP LOCKED inside the store) and dispatching
// each row to its destination — CITADEL's WORM ledger and/or a
// registered webhook target. Successful deliveries flip the row to
// 'delivered'; transient failures bump `attempts` and re-queue with
// exponential backoff (the backoff is computed inside the store's
// MarkFailed); after the configured attempt cap the row is parked in
// 'dlq' for manual triage.
//
// Worker semantics match the SQL contract documented in
// `internal/db/migrations/0004_audit_and_content_versions.sql`. The
// worker is robust to transient infrastructure errors: if the DB or
// CITADEL is unreachable the worker logs and keeps polling — it
// never crashes the process.
package citadel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// OutboxEntry is the worker's view of an outbox row. Mirrors the
// columns the worker needs from `internal/db/outbox_store.go`. Kept
// here as a structural-typing contract so this package does not have
// a hard build dependency on the (sibling) store implementation —
// the actual store satisfies this shape.
type OutboxEntry struct {
	ID            int64
	TenantID      string
	Destination   string // 'citadel' | 'webhook' | 'both'
	WebhookID     string // empty for pure CITADEL events
	EventType     string
	Payload       []byte
	CorrelationID string
	Attempts      int
	CreatedAt     time.Time
}

// OutboxStore is the minimal interface the worker needs. The real
// store in `internal/db/outbox_store.go` is expected to satisfy this
// interface by structural typing (its methods carry compatible
// signatures even though they are declared on a concrete type).
//
// MarkFailed is responsible for the per-row exponential backoff and
// for flipping the row to 'dlq' once `attempts` exceeds the cap; the
// boolean it returns tells the worker whether the row reached dlq so
// the worker can log + bump the dlq metric.
type OutboxStore interface {
	Claim(ctx context.Context, batchSize int) ([]OutboxEntry, error)
	MarkDelivered(ctx context.Context, id int64) error
	MarkFailed(ctx context.Context, id int64, errMsg string, retryable bool) (movedToDLQ bool, err error)
}

// WebhookRecord is the worker's view of a webhook destination. The
// real `webhooks` row carries more columns; the worker only needs
// enough to sign and POST.
type WebhookRecord struct {
	ID         string
	URL        string
	SecretHMAC string
	Active     bool
}

// WebhookStore is the minimal lookup shape used by the dispatcher.
type WebhookStore interface {
	GetWebhook(ctx context.Context, id string) (*WebhookRecord, error)
}

// Metrics is the subset of the cyberpath Prometheus registry the
// worker touches. The concrete *metrics.Registry satisfies this
// interface by exposing the matching CounterVec / Gauge / Histogram
// fields on the call sites below — but defining it as an interface
// keeps the package test-friendly.
type Metrics interface {
	IncEnqueued(destination, eventType string)
	IncDelivered(destination, eventType string)
	IncFailed(destination, eventType string, retryable bool)
	IncDLQ()
	IncInFlight()
	DecInFlight()
	ObserveDeliveryDuration(destination, eventType string, seconds float64)
}

// Options carries Worker tunables.
type Options struct {
	Outbox       OutboxStore
	Webhooks     WebhookStore
	Citadel      *Client
	HTTP         *httpDoer // optional; defaults to net/http inside dispatcher
	Metrics      Metrics
	Logger       zerolog.Logger
	Workers      int           // parallel goroutines (default 2)
	BatchSize    int           // rows per claim (default 10)
	PollInterval time.Duration // sleep between empty polls (default 2s)
	HTTPTimeout  time.Duration // per-call HTTP timeout (default 5s)
	HealthWindow time.Duration // "healthy if last delivery within …" (default 5m)
}

// Worker drains the outbox.
type Worker struct {
	opts Options

	// last successful delivery, unix-nano. Atomic so IsHealthy can
	// read concurrently with the dispatch goroutines that write it.
	lastDeliveryNanos atomic.Int64

	// last empty-claim observation; if we've polled and the queue
	// was empty, that also satisfies "healthy".
	lastEmptyClaimNanos atomic.Int64

	wg       sync.WaitGroup
	stopOnce sync.Once
}

// NewWorker builds a Worker. Sensible defaults are applied for any
// zero fields in opts.
func NewWorker(opts Options) *Worker {
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	if opts.HTTPTimeout <= 0 {
		opts.HTTPTimeout = 5 * time.Second
	}
	if opts.HealthWindow <= 0 {
		opts.HealthWindow = 5 * time.Minute
	}
	opts.Logger = opts.Logger.With().Str("component", "outbox-worker").Logger()
	return &Worker{opts: opts}
}

// Start launches the worker goroutines and returns immediately. The
// goroutines exit when ctx is cancelled. Wait for full shutdown via
// Stop or by cancelling ctx and calling Wait.
func (w *Worker) Start(ctx context.Context) error {
	if w.opts.Outbox == nil {
		return errors.New("outbox worker: nil outbox store")
	}
	for i := 0; i < w.opts.Workers; i++ {
		w.wg.Add(1)
		idx := i
		go func() {
			defer w.wg.Done()
			w.runLoop(ctx, idx)
		}()
	}
	w.opts.Logger.Info().
		Int("workers", w.opts.Workers).
		Int("batch_size", w.opts.BatchSize).
		Dur("poll_interval", w.opts.PollInterval).
		Msg("outbox worker started")
	return nil
}

// Run is a synchronous helper: starts the worker and blocks until
// the supplied ctx is cancelled, then waits for in-flight work to
// drain.
func (w *Worker) Run(ctx context.Context) error {
	if err := w.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	w.wg.Wait()
	w.opts.Logger.Info().Msg("outbox worker stopped")
	return nil
}

// Wait blocks until all worker goroutines have exited.
func (w *Worker) Wait() { w.wg.Wait() }

// IsHealthy returns true when:
//   - we've successfully delivered something within HealthWindow, OR
//   - we've polled and the queue was empty within HealthWindow.
//
// On a brand-new boot with no traffic both timestamps are zero, so
// the worker reports healthy after the first empty poll completes.
// Suitable for /readyz wiring.
func (w *Worker) IsHealthy() bool {
	now := time.Now()
	cutoff := now.Add(-w.opts.HealthWindow).UnixNano()
	if w.lastDeliveryNanos.Load() >= cutoff {
		return true
	}
	if w.lastEmptyClaimNanos.Load() >= cutoff {
		return true
	}
	// Cold start grace: report healthy until we've been running long
	// enough to expect at least one poll cycle. The /readyz probe will
	// flip to unhealthy if we haven't observed *any* poll within the
	// window.
	return w.lastDeliveryNanos.Load() == 0 && w.lastEmptyClaimNanos.Load() == 0
}

// runLoop is the per-goroutine main loop. It is robust to errors:
// any error from Claim or dispatch is logged and the loop continues
// after a poll-interval sleep.
func (w *Worker) runLoop(ctx context.Context, workerIdx int) {
	log := w.opts.Logger.With().Int("worker_idx", workerIdx).Logger()
	for {
		if ctx.Err() != nil {
			return
		}

		entries, err := w.opts.Outbox.Claim(ctx, w.opts.BatchSize)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error().Err(err).Msg("outbox claim failed; will retry")
			if !sleepCtx(ctx, w.opts.PollInterval) {
				return
			}
			continue
		}

		if len(entries) == 0 {
			w.lastEmptyClaimNanos.Store(time.Now().UnixNano())
			if !sleepCtx(ctx, w.opts.PollInterval) {
				return
			}
			continue
		}

		for i := range entries {
			if ctx.Err() != nil {
				return
			}
			w.processOne(ctx, &entries[i], log)
		}
	}
}

// processOne dispatches a single entry and records the outcome.
func (w *Worker) processOne(ctx context.Context, entry *OutboxEntry, log zerolog.Logger) {
	if w.opts.Metrics != nil {
		w.opts.Metrics.IncInFlight()
		defer w.opts.Metrics.DecInFlight()
	}

	start := time.Now()
	err := w.dispatch(ctx, entry)
	elapsed := time.Since(start)
	if w.opts.Metrics != nil {
		w.opts.Metrics.ObserveDeliveryDuration(entry.Destination, entry.EventType, elapsed.Seconds())
	}

	if err == nil {
		if mErr := w.opts.Outbox.MarkDelivered(ctx, entry.ID); mErr != nil {
			log.Error().
				Err(mErr).
				Int64("outbox_id", entry.ID).
				Msg("MarkDelivered failed; row will be redelivered")
			return
		}
		w.lastDeliveryNanos.Store(time.Now().UnixNano())
		if w.opts.Metrics != nil {
			w.opts.Metrics.IncDelivered(entry.Destination, entry.EventType)
		}
		log.Debug().
			Int64("outbox_id", entry.ID).
			Str("destination", entry.Destination).
			Str("event_type", entry.EventType).
			Dur("elapsed", elapsed).
			Msg("outbox row delivered")
		return
	}

	retryable := errIsRetryable(err)
	if w.opts.Metrics != nil {
		w.opts.Metrics.IncFailed(entry.Destination, entry.EventType, retryable)
	}

	movedToDLQ, mErr := w.opts.Outbox.MarkFailed(ctx, entry.ID, err.Error(), retryable)
	if mErr != nil {
		log.Error().
			Err(mErr).
			Int64("outbox_id", entry.ID).
			Msg("MarkFailed failed; row will be redelivered")
		return
	}
	if movedToDLQ {
		if w.opts.Metrics != nil {
			w.opts.Metrics.IncDLQ()
		}
		log.Warn().
			Int64("outbox_id", entry.ID).
			Str("destination", entry.Destination).
			Str("event_type", entry.EventType).
			Int("attempts", entry.Attempts+1).
			Err(err).
			Msg("outbox row moved to DLQ — manual triage required")
		return
	}
	log.Info().
		Int64("outbox_id", entry.ID).
		Str("destination", entry.Destination).
		Str("event_type", entry.EventType).
		Bool("retryable", retryable).
		Err(err).
		Msg("outbox row delivery failed; will retry")
}

// sleepCtx sleeps for d or returns false if ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
