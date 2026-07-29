// Package webhook fans out IOC / bundle / sighting events to registered
// ecosystem subscribers (APIGuard, IRFlow, NIS2 Compass, or any external
// consumer). Each delivery is HMAC-signed, tracked in webhook_deliveries,
// and retried with exponential backoff on transient failures.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// Event types fanned out to subscribers.
const (
	EventIOCCreated       = "ioc.created"
	EventIOCUpdated       = "ioc.updated"
	EventIOCRevoked       = "ioc.revoked"
	EventBundleImported   = "bundle.imported"
	EventSightingReported = "sighting.reported"
	EventAdvisoryIngested = "advisory.ingested"
	EventAdvisoryUpdated  = "advisory.updated"
)

// Event is the wire envelope sent to every subscriber.
type Event struct {
	ID        uuid.UUID       `json:"id"`
	Type      string          `json:"type"`
	CreatedAt time.Time       `json:"created_at"`
	Source    string          `json:"source"`
	Payload   json.RawMessage `json:"payload"`
}

// Dispatcher fans events out to matching subscribers and persists delivery
// attempts. It owns a bounded goroutine pool so hot-path callers never block.
type Dispatcher struct {
	webhooks *store.WebhookStore
	http     *http.Client
	logger   zerolog.Logger

	wg  sync.WaitGroup
	sem chan struct{}

	maxAttempts int
	baseBackoff time.Duration
}

// NewDispatcher builds a Dispatcher.
func NewDispatcher(webhooks *store.WebhookStore, logger zerolog.Logger) *Dispatcher {
	return &Dispatcher{
		webhooks:    webhooks,
		http:        &http.Client{Timeout: 15 * time.Second},
		logger:      logger.With().Str("component", "webhook").Logger(),
		sem:         make(chan struct{}, 64),
		maxAttempts: 4,
		baseBackoff: 500 * time.Millisecond,
	}
}

// Emit fans an event out to all matching subscribers asynchronously. It never
// blocks beyond the time required to look up matching subscribers and enqueue
// the goroutines (bounded to 64 in flight).
func (d *Dispatcher) Emit(ctx context.Context, eventType, source string, confidence int, payload any) {
	if d == nil || d.webhooks == nil {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		d.logger.Warn().Err(err).Str("event_type", eventType).Msg("marshal payload")
		return
	}
	subs, err := d.webhooks.MatchingSubscribers(ctx, eventType, confidence)
	if err != nil {
		d.logger.Warn().Err(err).Str("event_type", eventType).Msg("match subscribers")
		return
	}
	if len(subs) == 0 {
		return
	}

	event := &Event{
		ID:        uuid.New(),
		Type:      eventType,
		CreatedAt: time.Now().UTC(),
		Source:    source,
		Payload:   body,
	}
	for _, sub := range subs {
		select {
		case d.sem <- struct{}{}:
			d.wg.Add(1)
			go func(s *store.WebhookSubscriber) {
				defer d.wg.Done()
				defer func() { <-d.sem }()
				d.deliverWithRetry(s, event)
			}(sub)
		default:
			d.logger.Warn().Str("subscriber", sub.Name).Str("event_type", eventType).Msg("webhook queue saturated — event dropped")
			_ = d.recordOutcome(sub, event, "failed", 0, "queue saturated", time.Now().UTC(), nil)
		}
	}
}

// Drain waits for in-flight deliveries to finish or ctx to expire. Call during
// graceful shutdown so no event is lost mid-flight.
func (d *Dispatcher) Drain(ctx context.Context) {
	if d == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// deliverWithRetry POSTs the event, retrying on 5xx / network errors with
// exponential backoff. Every attempt is logged to webhook_deliveries.
func (d *Dispatcher) deliverWithRetry(sub *store.WebhookSubscriber, ev *Event) {
	envelope, err := json.Marshal(ev)
	if err != nil {
		d.logger.Warn().Err(err).Msg("marshal event")
		return
	}

	status := "retrying"
	for attempt := 1; attempt <= d.maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		code, respErr := d.deliverOnce(ctx, sub, ev.ID, envelope)
		cancel()

		now := time.Now().UTC()
		var deliveredAt *time.Time
		if respErr == nil && code >= 200 && code < 300 {
			status = "delivered"
			deliveredAt = &now
		} else if attempt == d.maxAttempts {
			status = "failed"
		}
		errMsg := ""
		if respErr != nil {
			errMsg = respErr.Error()
		} else if code >= 400 {
			errMsg = fmt.Sprintf("http %d", code)
		}

		if err := d.recordOutcome(sub, ev, status, code, errMsg, now, deliveredAt); err != nil {
			d.logger.Warn().Err(err).Msg("record delivery")
		}

		if status == "delivered" || status == "failed" {
			if status == "delivered" {
				d.logger.Info().Str("subscriber", sub.Name).Str("event_type", ev.Type).Int("attempt", attempt).Msg("delivered")
			} else {
				d.logger.Warn().Str("subscriber", sub.Name).Str("event_type", ev.Type).Str("error", errMsg).Msg("delivery failed")
			}
			return
		}

		// Backoff before next attempt: 0.5s, 1s, 2s.
		wait := d.baseBackoff * time.Duration(1<<(attempt-1))
		time.Sleep(wait)
	}
}

// deliverOnce POSTs the envelope once and returns the HTTP status code (0 on
// network error).
func (d *Dispatcher) deliverOnce(ctx context.Context, sub *store.WebhookSubscriber, eventID uuid.UUID, envelope []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(envelope))
	if err != nil {
		return 0, err
	}
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	sig := signPayload(sub.Secret, ts, envelope)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ThreatFlow-Event-ID", eventID.String())
	req.Header.Set("X-ThreatFlow-Timestamp", ts)
	req.Header.Set("X-ThreatFlow-Signature", sig)

	resp, err := d.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()
	return resp.StatusCode, nil
}

func (d *Dispatcher) recordOutcome(
	sub *store.WebhookSubscriber, ev *Event,
	status string, code int, errMsg string,
	lastAttempt time.Time, deliveredAt *time.Time,
) error {
	ls := &code
	if code == 0 {
		ls = nil
	}
	return d.webhooks.RecordDelivery(context.Background(), &store.WebhookDelivery{
		SubscriberID:  sub.ID,
		EventType:     ev.Type,
		EventID:       ev.ID,
		Payload:       ev.Payload,
		Status:        status,
		LastStatus:    ls,
		LastError:     errMsg,
		LastAttemptAt: &lastAttempt,
		DeliveredAt:   deliveredAt,
	})
}

// signPayload computes the HMAC-SHA256 signature that the subscriber verifies.
// Format: `sha256=<hex(HMAC(secret, ts + "." + body))>` — this is the
// ecosystem-wide webhook signature contract (see docs/webhook-spec.md and
// docs/security.md) shared by every X-<Platform>-Signature webhook header
// across opensecstack (IRFlow, VertGuard, CyberPath, APIGuard, the SDK, ...).
// It is deliberately distinct from the `hmac-sha256=` prefix used only by the
// CITADEL connector protocol (X-CITADEL-SIG, see internal/citadel/client.go)
// — do not conflate the two schemes.
func signPayload(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature is a helper for subscribers (re-exported so tests can use it).
func VerifySignature(secret, ts, signature string, body []byte) bool {
	want := signPayload(secret, ts, body)
	return hmac.Equal([]byte(want), []byte(signature))
}
