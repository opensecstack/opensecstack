package citadel

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

// Watcher polls the citadel_outbox table for pending events and submits
// them through the Client. State transitions:
//
//	pending → sending (MarkSending before submit)
//	sending → sent     (MarkSent on Confirmation{Delivered})
//	sending → failed   (MarkFailed on Confirmation{Dropped} after retries)
type Watcher struct {
	store  *db.OutboxStore
	client *Client
	tick   time.Duration
	logger zerolog.Logger

	mu       sync.Mutex
	inFlight map[string]uuid.UUID // event_id → outbox row id
}

func NewWatcher(store *db.OutboxStore, client *Client, tick time.Duration, logger zerolog.Logger) *Watcher {
	return &Watcher{
		store:    store,
		client:   client,
		tick:     tick,
		logger:   logger,
		inFlight: make(map[string]uuid.UUID),
	}
}

// Run starts the watcher loop. Should be invoked as `go w.Run(ctx)`.
func (w *Watcher) Run(ctx context.Context) {
	// Recover any 'sending' rows that a prior crash left orphaned.
	if n, err := w.store.RequeueSending(ctx); err != nil {
		w.logger.Error().Err(err).Msg("citadel: requeue sending failed")
	} else if n > 0 {
		w.logger.Info().Int64("count", n).Msg("citadel: requeued orphaned sending rows")
	}

	go w.consumeConfirmations(ctx)

	t := time.NewTicker(w.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tickOnce(ctx)
		}
	}
}

func (w *Watcher) tickOnce(ctx context.Context) {
	rows, err := w.store.Pending(ctx, 50)
	if err != nil {
		w.logger.Error().Err(err).Msg("citadel: pending fetch failed")
		return
	}
	for _, row := range rows {
		if err := w.store.MarkSending(ctx, row.ID, row.Attempts+1); err != nil {
			continue
		}
		w.mu.Lock()
		w.inFlight[row.EventID] = row.ID
		w.mu.Unlock()

		outcome, err := w.client.Submit(ctx, row.EventType, row.EventID, row.Payload)
		switch outcome {
		case SubmitDelivered, SubmitDryRun:
			_ = w.store.MarkSent(ctx, row.ID)
			w.untrack(row.EventID)
		case SubmitQueued:
			// Wait for confirmation channel; row stays in 'sending'.
		case SubmitDropped:
			msg := "dropped"
			if err != nil {
				msg = err.Error()
			}
			_ = w.store.MarkFailed(ctx, row.ID, msg)
			w.mu.Lock()
			delete(w.inFlight, row.EventID)
			w.mu.Unlock()
		}
	}
}

func (w *Watcher) consumeConfirmations(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case conf := <-w.client.Confirmations():
			w.mu.Lock()
			rowID, ok := w.inFlight[conf.EventID]
			if ok {
				delete(w.inFlight, conf.EventID)
			}
			w.mu.Unlock()
			if !ok {
				continue
			}
			switch conf.Outcome {
			case SubmitDelivered:
				_ = w.store.MarkSent(ctx, rowID)
			case SubmitDropped:
				msg := "dropped"
				if conf.Err != nil {
					msg = conf.Err.Error()
				}
				_ = w.store.MarkFailed(ctx, rowID, msg)
			}
		}
	}
}

func (w *Watcher) untrack(eventID string) {
	w.mu.Lock()
	delete(w.inFlight, eventID)
	w.mu.Unlock()
}
