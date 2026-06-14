// Package irflow holds the outbound HTTP client used to notify
// IRFlow that a CyberPath remediation track has been completed.
//
// HMAC scheme matches the ecosystem-wide pattern: signed input is
// timestamp + "." + body, HMAC-SHA256, hex-encoded, sent in
// X-Irflow-Signature with the timestamp in X-Irflow-Timestamp.
//
// Body canonicalisation: encoding/json's Marshal of the request
// struct is signed and sent verbatim. Field order = struct
// declaration order, so the on-wire bytes are deterministic.
//
// Wire in cmd/server/main.go via Options.IRFlowClient. The track
// completion handler will call NotifyRemediationCompleted when the
// completed track was assigned by an incident trigger.
package irflow

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
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Options configures the Client.
type Options struct {
	BaseURL     string
	HMACSecret  string
	HTTPTimeout time.Duration
	MaxRetries  int
	Logger      zerolog.Logger
}

// Client is safe for concurrent use.
type Client struct {
	baseURL    string
	hmacSecret string
	maxRetries int
	http       *http.Client
	logger     zerolog.Logger
}

// New constructs a Client.
func New(opts Options) *Client {
	to := opts.HTTPTimeout
	if to <= 0 {
		to = 5 * time.Second
	}
	retries := opts.MaxRetries
	if retries <= 0 {
		retries = 3
	}
	return &Client{
		baseURL:    opts.BaseURL,
		hmacSecret: opts.HMACSecret,
		maxRetries: retries,
		http:       &http.Client{Timeout: to},
		logger:     opts.Logger.With().Str("component", "irflow").Logger(),
	}
}

// remediationEvent is the wire body for /webhooks/cyberpath/remediation.
type remediationEvent struct {
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	IncidentID  string    `json:"incident_id"`
	CohortID    string    `json:"cohort_id"`
	CompletedAt time.Time `json:"completed_at"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// NotifyRemediationCompleted POSTs a remediation-complete event to
// IRFlow. The IRFlow side will append a timeline entry to the
// referenced incident.
func (c *Client) NotifyRemediationCompleted(ctx context.Context, incidentID, cohortID string, completedAt time.Time) error {
	if c.baseURL == "" {
		return fmt.Errorf("irflow/notify: base URL not configured")
	}
	ev := remediationEvent{
		EventID:     uuid.NewString(),
		EventType:   "cyberpath.incident_remediation_completed",
		IncidentID:  incidentID,
		CohortID:    cohortID,
		CompletedAt: completedAt,
		OccurredAt:  time.Now().UTC(),
	}
	body, err := canonicalJSON(ev)
	if err != nil {
		return fmt.Errorf("irflow/notify: marshal: %w", err)
	}
	resp, err := c.doSigned(ctx, http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", body, ev.EventID)
	if err != nil {
		return fmt.Errorf("irflow/notify: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("irflow/notify: status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (c *Client) doSigned(ctx context.Context, method, path string, body []byte, eventID string) (*http.Response, error) {
	var lastErr error
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Irflow-Timestamp", ts)
		req.Header.Set("X-Irflow-Signature", "sha256="+sign(body, ts, c.hmacSecret))
		if eventID != "" {
			req.Header.Set("X-Irflow-Event-Id", eventID)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			c.logger.Warn().Err(err).Int("attempt", attempt).Msg("irflow transport error; will retry")
			continue
		}
		if resp.StatusCode >= 500 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
			c.logger.Warn().Int("status", resp.StatusCode).Int("attempt", attempt).Msg("irflow 5xx; will retry")
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func canonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }

func sign(body []byte, timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
