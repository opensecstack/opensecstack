// Package citadel submits cyberpath.completion events to CITADEL's
// WORM audit log.
//
// v0.0.1 stub: when DryRun (or no BaseURL) the client logs the event
// and returns nil; otherwise it POSTs synchronously with HMAC-SHA256
// signing. Async batching + circuit breaker land in v1.0.0 — see
// docs/citadel-integration.md.
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
	"time"

	"github.com/rs/zerolog"
)

// Config carries CITADEL client tunables.
type Config struct {
	BaseURL     string
	HMACSecret  string
	KeyID       string
	ProjectID   string
	DryRun      bool
	HTTPTimeout time.Duration
}

// Event is the body shape POSTed to CITADEL for cyberpath.completion.
type Event struct {
	EventType     string         `json:"event_type"`
	Subject       string         `json:"subject"`
	Tenant        string         `json:"tenant,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
	CorrelationID string         `json:"correlation_id"`
	ProjectID     string         `json:"project_id,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
}

// Client is safe for concurrent use.
type Client struct {
	cfg    Config
	http   *http.Client
	logger zerolog.Logger
}

// New returns a configured Client.
func New(cfg Config, logger zerolog.Logger) *Client {
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	return &Client{
		cfg:    cfg,
		http:   &http.Client{Timeout: cfg.HTTPTimeout},
		logger: logger.With().Str("component", "citadel").Logger(),
	}
}

// Submit sends a cyberpath.completion event. In dev (DryRun or empty
// BaseURL) it just logs and returns nil. Otherwise POSTs synchronously.
func (c *Client) Submit(ctx context.Context, ev Event) error {
	if c.cfg.ProjectID != "" && ev.ProjectID == "" {
		ev.ProjectID = c.cfg.ProjectID
	}
	if c.cfg.DryRun || c.cfg.BaseURL == "" {
		c.logger.Info().
			Str("event_type", ev.EventType).
			Str("subject", ev.Subject).
			Msg("CITADEL submission (dry-run / standalone)")
		return nil
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	url := c.cfg.BaseURL + "/api/v1/worm/emit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CyberPath-Timestamp", ts)
	req.Header.Set("X-CyberPath-Signature", "sha256="+sign(body, ts, c.cfg.HMACSecret))
	if c.cfg.KeyID != "" {
		req.Header.Set("X-CyberPath-Key-Id", c.cfg.KeyID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 500 {
		return fmt.Errorf("citadel %d: %s", resp.StatusCode, string(respBody))
	}
	return errors.New("citadel " + strconv.Itoa(resp.StatusCode) + ": " + string(respBody))
}

// sign computes HMAC-SHA256 over (timestamp || "." || body).
func sign(body []byte, timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
