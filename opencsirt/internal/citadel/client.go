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
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// SubmitOutcome distinguishes synchronous delivery from queued/dropped.
//
// Watchers must NOT MarkSent on Queued — that only confirms the event
// was accepted for retry, not delivered. Pattern lifted from OpenScrub.
type SubmitOutcome int

const (
	SubmitDelivered SubmitOutcome = iota
	SubmitQueued
	SubmitDropped
	SubmitDryRun
)

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
	default:
		return "unknown"
	}
}

// Config holds the operator-supplied wiring for the Citadel client.
// HMACSecrets is a 3-slot rotation list: [primary, next, previous].
// If HMACSecrets is empty, HMACSecret (single legacy value) is used so
// existing deployments continue to work without a config change.
type Config struct {
	// 3-slot rotation. First non-empty entry is the signing key.
	HMACSecrets []string
	KeyIDs      []string

	// Legacy single-secret field — kept for backwards compatibility.
	HMACSecret string
	KeyID      string

	APIURL string
	// ProjectID is forwarded as the "project_id" field on every WORM emit
	// (see emitRequest in citadel/internal/api/handlers/worm.go). Defaults
	// to "opencsirt" if unset — see config.CitadelProjectID.
	ProjectID string
	DryRun    bool
}

// primarySecret returns the bytes to sign with.
// Walks HMACSecrets and returns the first non-empty slot;
// falls back to HMACSecret for backwards compatibility.
func (cfg *Config) primarySecret() []byte {
	for _, s := range cfg.HMACSecrets {
		if s != "" {
			return []byte(s)
		}
	}
	return []byte(cfg.HMACSecret)
}

// primaryKeyID returns the key-id to advertise in X-Key-ID.
// Mirrors primarySecret: first non-empty KeyIDs slot wins, then KeyID.
func (cfg *Config) primaryKeyID() string {
	for _, k := range cfg.KeyIDs {
		if k != "" {
			return k
		}
	}
	return cfg.KeyID
}

// SecretsAsBytes converts the string rotation list to the [][]byte shape
// the internal client uses (primary at [0]).
func (cfg *Config) SecretsAsBytes() [][]byte {
	primary := cfg.primarySecret()
	if len(primary) == 0 {
		return nil
	}
	return [][]byte{primary}
}

// NewFromConfig constructs a Client from the operator Config struct.
// Use this in main.go instead of calling New() directly.
func NewFromConfig(cfg Config, logger zerolog.Logger) *Client {
	projectID := cfg.ProjectID
	if projectID == "" {
		projectID = "opencsirt"
	}
	return New(cfg.APIURL, cfg.SecretsAsBytes(), cfg.primaryKeyID(), projectID, cfg.DryRun, logger)
}

// source identifies this producer in every WORM entry it emits — the
// "source" field in citadel/internal/api/handlers/worm.go's emitRequest.
const source = "opencsirt"

type Client struct {
	apiURL      string
	hmacSecrets [][]byte // sign with [0]
	keyID       string
	projectID   string
	dryRun      bool
	http        *http.Client
	logger      zerolog.Logger

	// Async retry buffer
	queue       chan *Envelope
	confirms    chan Confirmation
	maxRetries  int
}

type Envelope struct {
	EventType string
	EventID   string
	Payload   any
	attempt   int
}

type Confirmation struct {
	EventID string
	Outcome SubmitOutcome
	Err     error
}

func New(apiURL string, secrets [][]byte, keyID string, projectID string, dryRun bool, logger zerolog.Logger) *Client {
	if projectID == "" {
		projectID = "opencsirt"
	}
	c := &Client{
		apiURL:      apiURL,
		hmacSecrets: secrets,
		keyID:       keyID,
		projectID:   projectID,
		dryRun:      dryRun,
		http:        &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		queue:       make(chan *Envelope, 1024),
		confirms:    make(chan Confirmation, 1024),
		maxRetries:  5,
	}
	return c
}

// Submit attempts a synchronous delivery. On a transient failure the
// envelope is enqueued for async retry and the call returns SubmitQueued.
// On buffer overflow the call returns SubmitDropped and a Confirmation
// is published so the watcher can observe the loss.
func (c *Client) Submit(ctx context.Context, eventType, eventID string, payload any) (SubmitOutcome, error) {
	if c.dryRun {
		c.logger.Info().Str("event_type", eventType).Str("event_id", eventID).Msg("citadel: dry-run submit")
		return SubmitDryRun, nil
	}
	if c.apiURL == "" {
		return SubmitDryRun, nil
	}

	env := &Envelope{EventType: eventType, EventID: eventID, Payload: payload, attempt: 1}
	if err := c.deliver(ctx, env); err == nil {
		return SubmitDelivered, nil
	} else if !isTransient(err) {
		return SubmitDropped, err
	}

	// Transient — enqueue for retry.
	select {
	case c.queue <- env:
		return SubmitQueued, nil
	default:
		c.publish(Confirmation{EventID: eventID, Outcome: SubmitDropped, Err: errors.New("retry buffer full")})
		return SubmitDropped, errors.New("citadel: retry buffer full")
	}
}

// Run starts the async retry loop. Returns when ctx is done.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-c.queue:
			env.attempt++
			if err := c.deliver(ctx, env); err == nil {
				c.publish(Confirmation{EventID: env.EventID, Outcome: SubmitDelivered})
				backoff = time.Second
				continue
			}
			if env.attempt >= c.maxRetries {
				c.publish(Confirmation{EventID: env.EventID, Outcome: SubmitDropped, Err: errors.New("max retries exceeded")})
				continue
			}
			// Backoff before re-enqueueing.
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			select {
			case c.queue <- env:
			default:
				c.publish(Confirmation{EventID: env.EventID, Outcome: SubmitDropped, Err: errors.New("retry buffer full on reenqueue")})
			}
		}
	}
}

// Confirmations exposes durable delivery confirmations. The watcher
// reads from this channel to decide when to MarkSent / MarkFailed.
func (c *Client) Confirmations() <-chan Confirmation { return c.confirms }

// QueueDepth is exposed for /metrics/snapshot.
func (c *Client) QueueDepth() int { return len(c.queue) }

func (c *Client) publish(conf Confirmation) {
	select {
	case c.confirms <- conf:
	default:
		c.logger.Warn().Str("event_id", conf.EventID).Msg("citadel: confirmation channel full, dropping")
	}
}

// wormEmitRequest is the body CITADEL's POST /api/v1/worm/emit expects —
// see citadel/internal/api/handlers/worm.go's emitRequest. Field names must
// match exactly (source, event_type, project_id, payload).
type wormEmitRequest struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

func (c *Client) deliver(ctx context.Context, env *Envelope) error {
	payload, err := json.Marshal(env.Payload)
	if err != nil {
		return err
	}
	if len(c.hmacSecrets) == 0 {
		return errors.New("citadel: no hmac secrets configured")
	}

	body, err := json.Marshal(wormEmitRequest{
		Source:    source,
		EventType: env.EventType,
		ProjectID: c.projectID,
		Payload:   payload,
	})
	if err != nil {
		return err
	}

	// worm/emit takes a plain JSON body (see citadel/internal/api/server.go —
	// no HMAC verification is wired up on that route today). These headers
	// are kept for their audit/log value and forward-compatibility should
	// CITADEL add signature verification to worm/emit later; they are not
	// required for delivery to succeed.
	ts := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, c.hmacSecrets[0])
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiURL+"/api/v1/worm/emit", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Type", env.EventType)
	req.Header.Set("X-Event-ID", env.EventID)
	req.Header.Set("X-Key-ID", c.keyID)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("citadel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("citadel: transient %d", resp.StatusCode)
	}
	return fmt.Errorf("citadel: permanent %d", resp.StatusCode)
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
