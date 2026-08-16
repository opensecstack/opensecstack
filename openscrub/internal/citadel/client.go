// Package citadel emits openscrub.* WORM events to CITADEL.
//
// Wire format:
//
//	POST {BaseURL}/api/v1/worm/emit
//	Content-Type: application/json
//	body: {"source":"openscrub","event_type":<event's "type">,
//	       "project_id":<Config.ProjectID>,"payload":<the marshalled event>}
//
// This is CITADEL's actual WORM ingest endpoint — see
// citadel/internal/api/handlers/worm.go (emitRequest/emitResponse) for the
// server-side contract this mirrors. This client previously posted to
// /api/v1/evidence (and, per an earlier doc comment, /api/v1/events) —
// neither of those routes exists on CITADEL, so every submission failed
// silently. /api/v1/worm/emit is a plain immutable audit-log append; it
// does not perform an authorization decision (that's
// POST /api/v1/marshal/evaluate, used separately for governed actions —
// see internal/api/handlers/handlers.go Rules.Create).
//
// X-Source/X-Signature/X-Timestamp are still computed and sent (Sign,
// below) over the final wrapped body for defense-in-depth / forward
// compatibility, but note CITADEL's /worm/emit handler does not currently
// verify them — there is no signature or replay-window enforcement on
// this endpoint server-side today.
//
// Each event has a UUIDv4 `id` (inside the payload) so retries are
// correlated for logging/metrics, though CITADEL ingest idempotency is
// not guaranteed by that field on this endpoint.
package citadel

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

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/metrics"
)

// SubmitOutcome distinguishes the three terminal outcomes of Submit so
// callers (the mitigation watcher, the rules-service rule_change emit
// path) can avoid lying to the CITADEL evidence contract.
type SubmitOutcome int

const (
	// SubmitDelivered: synchronous 2xx from CITADEL; durable.
	SubmitDelivered SubmitOutcome = iota
	// SubmitQueued: transient failure; event accepted for async retry.
	// Caller must NOT mark the source-of-truth row as emitted yet —
	// wait for a DeliveryConfirmation on the channel from
	// Client.Confirmations() (or treat the row as still pending).
	SubmitQueued
	// SubmitDropped: the retry buffer was at capacity and the oldest
	// queued event was evicted to admit this one. Counted in metrics
	// as a permanent loss; callers should surface it to ops.
	SubmitDropped
	// SubmitDryRun: dry-run / no BaseURL configured; logged only.
	// Treated as "delivered" for emit-decision purposes (there is no
	// real CITADEL endpoint to wait on).
	SubmitDryRun
)

// String renders the outcome for log/metric labels.
func (o SubmitOutcome) String() string {
	switch o {
	case SubmitDelivered:
		return "delivered"
	case SubmitQueued:
		return "queued"
	case SubmitDropped:
		return "dropped"
	case SubmitDryRun:
		return "dry_run"
	}
	return "unknown"
}

// DeliveryConfirmation is published on Client.Confirmations() once the
// retry loop reaches a terminal state for an event that Submit returned
// SubmitQueued for. Callers correlate via EventID (the envelope id).
type DeliveryConfirmation struct {
	EventID   string
	Delivered bool
	Attempts  int
	Err       error
}

// Config carries client tunables.
type Config struct {
	BaseURL string
	// ProjectID is sent as the `project_id` field on every
	// POST /api/v1/worm/emit call. Defaults to "openscrub" when empty
	// (see New).
	ProjectID string
	// HMACSecret is the legacy single-key knob. When HMACSecrets is
	// non-empty it takes precedence; HMACSecret is then treated as a
	// fallback so existing single-key deployments keep working.
	HMACSecret string
	// HMACSecrets is the 3-slot rotation list ordered
	// [primary, next, previous]. Submit signs with the first non-empty
	// entry (the primary). The remaining entries are advertised to
	// CITADEL via the X-Key-Id header and must be present in the
	// CITADEL-side trust list during rotation. Mirrors the JWT
	// rotation contract in internal/auth.
	HMACSecrets []string
	KeyID       string
	// KeyIDs aligns with HMACSecrets. KeyIDs[i] is sent as X-Key-Id
	// when HMACSecrets[i] is the active signing key. When empty, the
	// scalar KeyID is used for the primary slot only and rotation
	// MUST happen via secret-only swap (CITADEL accepts signatures
	// from any trusted secret regardless of key id).
	KeyIDs      []string
	NodeName    string
	DryRun      bool
	HTTPTimeout time.Duration
	// RetryBufferSize bounds the in-memory retry queue used when the
	// CITADEL endpoint returns a transient (5xx / network) error.
	// Defaults to 1024. Submit() drops the oldest queued event when
	// the buffer is full and bumps citadel_emit_total{outcome="dropped"}.
	RetryBufferSize int
	// MaxRetries is the per-event retry cap before the event is
	// permanently dropped. Defaults to 5.
	MaxRetries int
	// RetryBaseDelay is the first backoff interval; subsequent delays
	// double up to RetryMaxDelay. Defaults to 2s / 60s.
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	// ConfirmDrainTimeout bounds how long the retry loop will block
	// trying to publish a DeliveryConfirmation when the watcher's
	// drainer is slow. Defaults to 5s. Increase if MarkSent/MarkFailed
	// can legitimately stall (e.g. failover pause), but be aware that
	// the retry loop is single-threaded — back-pressure here delays
	// every other event in the queue.
	ConfirmDrainTimeout time.Duration
}

// Client is safe for concurrent use.
type Client struct {
	cfg    Config
	http   *http.Client
	logger zerolog.Logger

	queue   chan retryItem
	confirm chan DeliveryConfirmation
	once    sync.Once
}

type retryItem struct {
	body     []byte
	eventID  string
	attempts int
}

// New returns a configured Client. When BaseURL is empty or DryRun is
// true, Submit logs and returns SubmitDryRun. Callers must invoke
// StartRetryLoop once before Submit if they want transient failures to
// be retried.
func New(cfg Config, logger zerolog.Logger) *Client {
	if cfg.ProjectID == "" {
		cfg.ProjectID = "openscrub"
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if cfg.RetryBufferSize <= 0 {
		cfg.RetryBufferSize = 1024
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 2 * time.Second
	}
	if cfg.RetryMaxDelay <= 0 {
		cfg.RetryMaxDelay = 60 * time.Second
	}
	return &Client{
		cfg:     cfg,
		http:    &http.Client{Timeout: cfg.HTTPTimeout},
		logger:  logger.With().Str("component", "citadel").Logger(),
		queue:   make(chan retryItem, cfg.RetryBufferSize),
		confirm: make(chan DeliveryConfirmation, cfg.RetryBufferSize),
	}
}

// Confirmations returns a receive-only channel of DeliveryConfirmation
// values produced by the retry loop. The watcher / outbox layer drains
// it to flip persisted state from `pending` to `sent` or `failed`. The
// channel is buffered (size = RetryBufferSize); if no consumer drains
// it, confirmations are dropped (and counted as
// citadel_emit_total{outcome="confirm_dropped"}) to keep the retry
// loop from stalling.
func (c *Client) Confirmations() <-chan DeliveryConfirmation { return c.confirm }

// QueueDepth returns the current retry-queue length. Used by
// /api/v1/metrics/snapshot.
func (c *Client) QueueDepth() int { return len(c.queue) }

// StartRetryLoop spawns a goroutine that drains the retry queue.
// Idempotent — only the first call has effect.
func (c *Client) StartRetryLoop(ctx context.Context) {
	c.once.Do(func() {
		go c.retryLoop(ctx)
	})
}

func (c *Client) retryLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-c.queue:
			delay := c.cfg.RetryBaseDelay << item.attempts
			if delay > c.cfg.RetryMaxDelay {
				delay = c.cfg.RetryMaxDelay
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			err := c.send(ctx, item.body)
			if err == nil {
				c.publishConfirmation(DeliveryConfirmation{
					EventID:   item.eventID,
					Delivered: true,
					Attempts:  item.attempts + 1,
				})
				continue
			}
			item.attempts++
			if item.attempts >= c.cfg.MaxRetries {
				c.logger.Error().Err(err).Int("attempts", item.attempts).
					Str("event_id", item.eventID).
					Msg("citadel event dropped after max retries")
				c.publishConfirmation(DeliveryConfirmation{
					EventID:   item.eventID,
					Delivered: false,
					Attempts:  item.attempts,
					Err:       err,
				})
				continue
			}
			if !c.enqueue(item) {
				// Eviction during re-enqueue: surface as dropped.
				c.publishConfirmation(DeliveryConfirmation{
					EventID:   item.eventID,
					Delivered: false,
					Attempts:  item.attempts,
					Err:       errors.New("retry buffer overflow"),
				})
			}
		}
	}
}

// confirmDrainTimeout bounds how long publishConfirmation will block
// trying to hand a receipt to the watcher's drainer when the channel
// is full. Long enough that a slow Postgres UPDATE doesn't leak
// confirmations, short enough that we never stall the retry loop on a
// dead consumer. Tunable via Config.ConfirmDrainTimeout.
const defaultConfirmDrainTimeout = 5 * time.Second

func (c *Client) publishConfirmation(d DeliveryConfirmation) {
	// Fast path: drainer is keeping up.
	select {
	case c.confirm <- d:
		return
	default:
	}
	// Slow path: drainer is behind. Block for a bounded window so a
	// momentarily slow MarkSent / MarkFailed doesn't silently drop the
	// receipt — the previous "drop on full" behaviour orphaned the
	// source row in 'pending' forever, which is exactly the bug the
	// retry buffer is meant to prevent. If we still can't drain after
	// the timeout the receipt is counted as lost and the row will be
	// retried after the next watcher tick (which re-selects pending
	// rows it doesn't know about — see PendingForEmit).
	timeout := c.cfg.ConfirmDrainTimeout
	if timeout <= 0 {
		timeout = defaultConfirmDrainTimeout
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case c.confirm <- d:
	case <-t.C:
		metrics.CitadelEmitTotal.WithLabelValues("confirm_dropped").Inc()
		c.logger.Error().Str("event_id", d.EventID).
			Dur("waited", timeout).
			Msg("delivery confirmation dropped — drainer back-pressured")
	}
}

// enqueue tries to push item onto the retry queue. Returns true if the
// item was admitted without evicting another. When the queue is full,
// the oldest item is evicted and a confirmation is published for it
// (so its source row is marked `failed` rather than orphaned as
// `pending` forever). Returns false if eviction occurred.
func (c *Client) enqueue(item retryItem) bool {
	select {
	case c.queue <- item:
		return true
	default:
	}
	// Buffer full: evict oldest and surface it.
	var evicted retryItem
	select {
	case evicted = <-c.queue:
		c.publishConfirmation(DeliveryConfirmation{
			EventID:   evicted.eventID,
			Delivered: false,
			Attempts:  evicted.attempts,
			Err:       errors.New("retry buffer overflow — evicted to admit newer event"),
		})
	default:
	}
	select {
	case c.queue <- item:
	default:
	}
	return false
}

// Submit posts one event. event must marshal to JSON. Returns one of:
//   - (SubmitDelivered, nil)  — synchronous 2xx, durable.
//   - (SubmitQueued,    nil)  — transient failure; queued for retry.
//     Caller must wait for a DeliveryConfirmation before treating the
//     event as durably emitted.
//   - (SubmitDropped,   err)  — buffer overflow on enqueue.
//   - (SubmitDryRun,    nil)  — dry-run / no BaseURL configured.
//   - (SubmitDelivered, err)  — permanent failure (4xx); not retried.
//
// The legacy contract (caller treats nil as "ok to mark emitted") is
// broken on purpose — see BLOCKER 2 in the migration changelog.
func (c *Client) Submit(ctx context.Context, event any) (SubmitOutcome, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return SubmitDelivered, fmt.Errorf("marshal event: %w", err)
	}
	if c.cfg.DryRun || c.cfg.BaseURL == "" {
		c.logger.Info().RawJSON("event", body).Msg("CITADEL submission (dry-run / standalone)")
		return SubmitDryRun, nil
	}
	wormBody, err := wrapWORMEmit(body, c.cfg.ProjectID)
	if err != nil {
		return SubmitDelivered, fmt.Errorf("wrap worm emit envelope: %w", err)
	}
	if err := c.send(ctx, wormBody); err != nil {
		if isTransient(err) {
			c.logger.Warn().Err(err).Msg("citadel submit transient — queued for retry")
			eventID := extractEventID(body)
			if !c.enqueue(retryItem{body: wormBody, eventID: eventID}) {
				return SubmitDropped, err
			}
			return SubmitQueued, nil
		}
		return SubmitDelivered, err
	}
	return SubmitDelivered, nil
}

// wormEmitRequest is the body posted to POST /api/v1/worm/emit. Field
// names and JSON tags MUST match citadel/internal/api/handlers/worm.go's
// emitRequest exactly — that is the server-side source of truth this
// mirrors.
type wormEmitRequest struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id"`
	Payload   json.RawMessage `json:"payload"`
}

// wrapWORMEmit wraps a marshalled openscrub.* event (payload) in the
// envelope CITADEL's /worm/emit endpoint expects. event_type is pulled
// from the event's own `type` field (every openscrub.* event embeds
// EventEnvelope, which has one).
func wrapWORMEmit(payload []byte, projectID string) ([]byte, error) {
	return json.Marshal(wormEmitRequest{
		Source:    "openscrub",
		EventType: extractEventType(payload),
		ProjectID: projectID,
		Payload:   payload,
	})
}

// extractEventID pulls the envelope `id` field out of a marshalled
// event. Best-effort — empty string if the body isn't an object with an
// `id` key. Used purely for log / confirmation correlation.
func extractEventID(body []byte) string {
	var probe struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.ID
}

// extractEventType pulls the envelope `type` field out of a marshalled
// event (e.g. "openscrub.rule_change"). Best-effort — empty string if
// the body isn't an object with a `type` key.
func extractEventType(body []byte) string {
	var probe struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.Type
}

// send performs one POST attempt and returns either nil, a transient
// error (wrapped via transientError), or a permanent error. body must
// already be wrapped via wrapWORMEmit.
func (c *Client) send(ctx context.Context, body []byte) error {
	url := c.cfg.BaseURL + "/api/v1/worm/emit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	secret, keyID := c.primarySecret()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Source", "openscrub")
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", Sign(secret, ts, body))
	if keyID != "" {
		req.Header.Set("X-Key-Id", keyID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return transientError{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	httpErr := errors.New("citadel " + strconv.Itoa(resp.StatusCode) + ": " + string(respBody))
	if resp.StatusCode >= 500 {
		return transientError{err: httpErr}
	}
	return httpErr
}

// primarySecret returns the active signing secret + matching key id.
// Lookup order: HMACSecrets[0] (with KeyIDs[0]) → legacy HMACSecret
// (with KeyID). An empty primary returns ("", "") and Sign produces a
// HMAC over the empty key, which CITADEL will reject — surfacing the
// misconfiguration loudly in evidence-server logs.
func (c *Client) primarySecret() (string, string) {
	for i, s := range c.cfg.HMACSecrets {
		if s == "" {
			continue
		}
		kid := ""
		if i < len(c.cfg.KeyIDs) {
			kid = c.cfg.KeyIDs[i]
		}
		if kid == "" {
			kid = c.cfg.KeyID
		}
		return s, kid
	}
	return c.cfg.HMACSecret, c.cfg.KeyID
}

type transientError struct{ err error }

func (e transientError) Error() string { return e.err.Error() }
func (e transientError) Unwrap() error { return e.err }

func isTransient(err error) bool {
	var t transientError
	return errors.As(err, &t)
}

// Sign computes HMAC-SHA256(secret, timestamp || "." || body) and
// returns the hex digest. The timestamp is included in the signed
// payload so an attacker cannot replay a captured (body, signature)
// pair under a different X-Timestamp header inside the ±5min window.
// Exported so tests and the audit-side verification path share one
// implementation.
func Sign(secret, timestamp string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
