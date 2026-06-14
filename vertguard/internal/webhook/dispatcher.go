package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// SubscriberLister is the read surface the dispatcher needs.
// Implemented by *Store; tests can stub it.
type SubscriberLister interface {
	ListByEventType(ctx context.Context, eventType string) ([]Subscriber, error)
}

// OutboxRepo is the outbox surface the dispatcher needs.
type OutboxRepo interface {
	EnqueueOutbox(ctx context.Context, row *OutboxRow) error
	FetchPendingOutbox(ctx context.Context, limit int) ([]OutboxRow, error)
	MarkDelivered(ctx context.Context, id uuid.UUID) error
	MarkAttempt(ctx context.Context, id uuid.UUID, attemptErr string, backoff time.Duration) error
	OutboxSize(ctx context.Context) (int, error)
}

// Metrics is the subset of metrics.Registry the dispatcher touches.
type Metrics interface {
	IncWebhookDispatch(result string)
	ObserveWebhookLatency(seconds float64)
	SetWebhookOutboxSize(n int)
	IncWebhookRotation()
}

// Config carries dispatcher tunables.
type Config struct {
	Enabled             bool
	MaxRetries          int
	BackoffBase         time.Duration
	OutboxFlushInterval time.Duration
	RequestTimeout      time.Duration
}

// Dispatcher delivers events to subscribers with retries + outbox.
// Safe for concurrent use.
type Dispatcher struct {
	cfg     Config
	subs    SubscriberLister
	outbox  OutboxRepo
	http    *http.Client
	logger  zerolog.Logger
	metrics Metrics

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewDispatcher wires the delivery loop. Call Start to launch the
// outbox-flush goroutine; Stop to drain.
func NewDispatcher(cfg Config, subs SubscriberLister, outbox OutboxRepo, logger zerolog.Logger, metrics Metrics) *Dispatcher {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 200 * time.Millisecond
	}
	if cfg.OutboxFlushInterval <= 0 {
		cfg.OutboxFlushInterval = 5 * time.Second
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 5 * time.Second
	}
	return &Dispatcher{
		cfg:     cfg,
		subs:    subs,
		outbox:  outbox,
		http:    &http.Client{Timeout: cfg.RequestTimeout},
		logger:  logger.With().Str("component", "webhook_dispatcher").Logger(),
		metrics: metrics,
		stopCh:  make(chan struct{}),
	}
}

// Publish fans out one event to every matching subscriber. For each
// subscriber it (a) enqueues an outbox row so a crash mid-loop is
// recoverable, then (b) attempts inline delivery with retry. On
// success the row is marked delivered; on permanent failure the row
// stays pending and the background flusher will retry.
func (d *Dispatcher) Publish(ctx context.Context, ev Event) {
	if d == nil || !d.cfg.Enabled {
		return
	}
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		d.logger.Warn().Err(err).Msg("marshal event")
		return
	}
	subs, err := d.subs.ListByEventType(ctx, ev.Type)
	if err != nil {
		d.logger.Warn().Err(err).Str("event_type", ev.Type).Msg("list subscribers")
		return
	}
	for i := range subs {
		sub := subs[i]
		row := &OutboxRow{
			SubscriberID: sub.ID,
			EventID:      ev.ID,
			EventType:    ev.Type,
			Payload:      body,
		}
		if err := d.outbox.EnqueueOutbox(ctx, row); err != nil {
			d.logger.Warn().Err(err).Str("subscriber_id", sub.ID.String()).Msg("enqueue outbox")
			continue
		}
		d.deliverWithRetry(ctx, &sub, row, body)
	}
}

// deliverWithRetry runs up to MaxRetries attempts. On terminal success
// the outbox row is marked delivered; on terminal failure the last
// error is recorded and the row stays pending for the background
// flusher to pick up.
func (d *Dispatcher) deliverWithRetry(ctx context.Context, sub *Subscriber, row *OutboxRow, body []byte) {
	var lastErr error
	for attempt := 0; attempt < d.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := d.cfg.BackoffBase * time.Duration(1<<attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
		start := time.Now()
		retryable, err := d.deliverOnce(ctx, sub, row, body)
		if d.metrics != nil {
			d.metrics.ObserveWebhookLatency(time.Since(start).Seconds())
		}
		if err == nil {
			if d.metrics != nil {
				d.metrics.IncWebhookDispatch("ok")
			}
			if mErr := d.outbox.MarkDelivered(ctx, row.ID); mErr != nil {
				d.logger.Warn().Err(mErr).Msg("mark delivered")
			}
			return
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	if d.metrics != nil {
		d.metrics.IncWebhookDispatch("fail")
	}
	backoff := d.cfg.BackoffBase * time.Duration(1<<d.cfg.MaxRetries)
	if mErr := d.outbox.MarkAttempt(ctx, row.ID, lastErr.Error(), backoff); mErr != nil {
		d.logger.Warn().Err(mErr).Msg("mark attempt")
	}
}

// deliverOnce performs one HTTP attempt. retryable = true on network
// errors and 5xx; false on 4xx (subscriber rejected the event — no
// point hammering them with the same payload).
func (d *Dispatcher) deliverOnce(ctx context.Context, sub *Subscriber, row *OutboxRow, body []byte) (retryable bool, err error) {
	secret, kid := sub.PrimarySecret()
	if secret == "" {
		// Refuse to send unsigned. Permanent failure — operator must
		// configure a primary slot before the subscriber receives.
		return false, errors.New("webhook: subscriber has no primary HMAC slot configured")
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := signEvent(secret, ts, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VertGuard-Signature", "sha256="+sig)
	req.Header.Set("X-VertGuard-Key-Id", kid)
	req.Header.Set("X-VertGuard-Timestamp", ts)
	req.Header.Set("X-VertGuard-Event-Id", row.EventID)

	resp, err := d.http.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	if resp.StatusCode >= 500 {
		return true, fmt.Errorf("subscriber %s returned %d", sub.ID, resp.StatusCode)
	}
	return false, fmt.Errorf("subscriber %s returned %d", sub.ID, resp.StatusCode)
}

// signEvent builds the same Stripe-style "<ts>.<body>" canonical input
// the inbound receiver verifies; symmetric so the existing receiver
// could be used as a self-test target.
func signEvent(secret, ts string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Start launches the background outbox flusher. Safe to call once.
func (d *Dispatcher) Start() {
	if d == nil || !d.cfg.Enabled {
		return
	}
	d.wg.Add(1)
	go d.flushLoop()
}

// Stop signals the flusher to drain and waits.
func (d *Dispatcher) Stop() {
	if d == nil {
		return
	}
	select {
	case <-d.stopCh:
		// already closed
	default:
		close(d.stopCh)
	}
	d.wg.Wait()
}

func (d *Dispatcher) flushLoop() {
	defer d.wg.Done()
	t := time.NewTicker(d.cfg.OutboxFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.flushOnce(context.Background())
		}
	}
}

// flushOnce drains pending outbox rows. Each row is re-delivered with
// its original payload — subscriber config is re-read so a rotation in
// the meantime takes effect.
func (d *Dispatcher) flushOnce(ctx context.Context) {
	rows, err := d.outbox.FetchPendingOutbox(ctx, 100)
	if err != nil {
		d.logger.Warn().Err(err).Msg("fetch pending outbox")
		return
	}
	if size, sErr := d.outbox.OutboxSize(ctx); sErr == nil && d.metrics != nil {
		d.metrics.SetWebhookOutboxSize(size)
	}
	for i := range rows {
		row := rows[i]
		// Look up subscriber on each retry — picks up any rotations
		// that happened since enqueue.
		var sub *Subscriber
		if g, ok := d.subs.(interface {
			Get(ctx context.Context, id uuid.UUID) (*Subscriber, error)
		}); ok {
			s, err := g.Get(ctx, row.SubscriberID)
			if err != nil {
				d.logger.Warn().Err(err).Str("subscriber_id", row.SubscriberID.String()).Msg("lookup subscriber for retry")
				continue
			}
			sub = s
		} else {
			d.logger.Warn().Msg("subscriber lister does not support Get; skipping outbox flush")
			continue
		}
		d.deliverWithRetry(ctx, sub, &row, row.Payload)
	}
}

// RecordRotation increments the rotation counter. Called by the admin
// handler after a successful Store.Rotate.
func (d *Dispatcher) RecordRotation() {
	if d != nil && d.metrics != nil {
		d.metrics.IncWebhookRotation()
	}
}
