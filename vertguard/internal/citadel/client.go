// Package citadel emits immutable evidence records to CITADEL's WORM
// audit log. The client is fire-and-forget from the caller's view: an
// async wrapper buffers events and a background goroutine flushes
// them with bounded retries. On hard shutdown unflushed events are
// drained with a 10s grace period.
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
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/breaker"
)

// Config carries CITADEL client tunables. Mirrors the fields used by
// internal/config.CitadelConfig but kept independent so tests can
// build a Client without pulling viper.
type Config struct {
	BaseURL string
	// HMACSecret is the legacy single-key knob. When HMACSecrets is
	// non-empty it takes precedence; HMACSecret remains as a fallback
	// so existing single-key deployments keep working.
	HMACSecret string
	// HMACSecrets is the 3-slot rotation list ordered
	// [primary, next, previous]. Sign() picks the first non-empty entry
	// as the active signing key. Mirrors the JWT verifier's rotation
	// contract in internal/auth so operators can roll the CITADEL HMAC
	// without restart coordination.
	HMACSecrets []string
	// KeyID is the legacy single key id. KeyIDs aligns positionally with
	// HMACSecrets; when both are empty no X-Key-Id header is sent.
	KeyID       string
	KeyIDs      []string
	ProjectID   string
	DryRun      bool
	AsyncBuffer int
	HTTPTimeout time.Duration
}

// primarySecret returns the active signing secret + matching key id.
// Lookup order: HMACSecrets[i] (with KeyIDs[i]) for the first non-empty
// slot, else the legacy scalar HMACSecret/KeyID. Empty primary returns
// ("", "") and the resulting HMAC will be rejected upstream — surfacing
// the misconfiguration loudly rather than silently signing with "".
func (c Config) primarySecret() (string, string) {
	for i, s := range c.HMACSecrets {
		if s == "" {
			continue
		}
		kid := ""
		if i < len(c.KeyIDs) {
			kid = c.KeyIDs[i]
		}
		if kid == "" {
			kid = c.KeyID
		}
		return s, kid
	}
	return c.HMACSecret, c.KeyID
}

// Metrics is the subset of vertguard's Prometheus registry the
// CITADEL client touches. Implementations adapt prom counters to
// this interface.
type Metrics interface {
	IncWORMEmit(eventType, result string)
	IncCitadelCall(target, result string)
	ObserveCitadelLatency(target string, durationSec float64)
	SetCitadelQueueDepth(n int)
}

// Evidence is the body shape POSTed to CITADEL's WORM emit endpoint.
type Evidence struct {
	EventType     string    `json:"event_type"`
	Subject       string    `json:"subject"`
	Verdict       string    `json:"verdict"`
	Score         float64   `json:"score"`
	Categories    []string  `json:"categories"`
	Patterns      []string  `json:"patterns"`
	Tenant        string    `json:"tenant,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	CorrelationID string    `json:"correlation_id"`
	ProjectID     string    `json:"project_id,omitempty"`
}

// Client is safe for concurrent use.
type Client struct {
	cfg     Config
	http    *http.Client
	logger  zerolog.Logger
	metrics Metrics
	breaker *breaker.Breaker

	queue   chan Evidence
	wg      sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
}

// New returns a Client and starts its background drain goroutine.
// Closing the client (Close) is required for graceful shutdown.
func New(cfg Config, logger zerolog.Logger, metrics Metrics) *Client {
	if cfg.AsyncBuffer <= 0 {
		cfg.AsyncBuffer = 1000
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	c := &Client{
		cfg:     cfg,
		http:    &http.Client{Timeout: cfg.HTTPTimeout},
		logger:  logger.With().Str("component", "citadel").Logger(),
		metrics: metrics,
		breaker: breaker.New(breaker.Config{
			Name:          "citadel.worm_emit",
			FailThreshold: 5,
			CoolDown:      30 * time.Second,
		}),
		queue: make(chan Evidence, cfg.AsyncBuffer),
	}
	c.wg.Add(1)
	go c.drain()
	return c
}

// EmitAsync enqueues evidence for background delivery. Returns true
// if accepted, false if the buffer is full (caller decides whether
// to drop or retry).
func (c *Client) EmitAsync(_ context.Context, ev Evidence) bool {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return false
	}
	c.closeMu.Unlock()

	if c.cfg.ProjectID != "" && ev.ProjectID == "" {
		ev.ProjectID = c.cfg.ProjectID
	}
	select {
	case c.queue <- ev:
		if c.metrics != nil {
			c.metrics.SetCitadelQueueDepth(len(c.queue))
		}
		return true
	default:
		if c.metrics != nil {
			c.metrics.IncWORMEmit(ev.EventType, "dropped_buffer_full")
		}
		c.logger.Warn().Str("event_type", ev.EventType).Msg("WORM emit dropped: buffer full")
		return false
	}
}

// EmitWORM POSTs synchronously with retries. Used by tests and by
// the drain goroutine.
func (c *Client) EmitWORM(ctx context.Context, ev Evidence) error {
	if c.cfg.DryRun {
		c.logger.Debug().Str("event_type", ev.EventType).Msg("WORM dry-run")
		if c.metrics != nil {
			c.metrics.IncWORMEmit(ev.EventType, "dry_run")
		}
		return nil
	}
	if c.cfg.BaseURL == "" {
		return errors.New("citadel: base URL not set")
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	const maxAttempts = 3
	backoff := []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff[attempt-1]): // #nosec G602 -- attempt ranges 1..maxAttempts-1 here (guarded by "attempt > 0" above, loop bound is maxAttempts=3), so attempt-1 is always a valid index into the 3-element backoff slice
			}
			if c.metrics != nil {
				c.metrics.IncWORMEmit(ev.EventType, "retry")
			}
		}

		start := time.Now()
		var retryable bool
		err := c.breaker.Execute(func() error {
			r, e := c.do(ctx, body)
			retryable = r
			return e
		})
		if c.metrics != nil {
			c.metrics.ObserveCitadelLatency("worm_emit", time.Since(start).Seconds())
		}
		if err == nil {
			if c.metrics != nil {
				c.metrics.IncWORMEmit(ev.EventType, "ok")
				c.metrics.IncCitadelCall("worm_emit", "ok")
			}
			return nil
		}
		// Breaker open short-circuits; no point in retrying within the
		// same call window — the breaker holds the cool-down.
		if errors.Is(err, breaker.ErrOpen) {
			if c.metrics != nil {
				c.metrics.IncCitadelCall("worm_emit", "breaker_open")
			}
			return err
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	if c.metrics != nil {
		c.metrics.IncWORMEmit(ev.EventType, "fail")
		c.metrics.IncCitadelCall("worm_emit", "fail")
	}
	return lastErr
}

// do performs one HTTP attempt. retryable=true on network errors and
// 5xx; false on 4xx and other terminal failures.
func (c *Client) do(ctx context.Context, body []byte) (retryable bool, err error) {
	url := c.cfg.BaseURL + "/api/v1/worm/emit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	secret, keyID := c.cfg.primarySecret()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VertGuard-Signature", "sha256="+sign(body, secret))
	if keyID != "" {
		req.Header.Set("X-Key-Id", keyID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return false, nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 500 {
		return true, fmt.Errorf("citadel %d: %s", resp.StatusCode, string(respBody))
	}
	return false, fmt.Errorf("citadel %d: %s", resp.StatusCode, string(respBody))
}

func sign(body []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Client) drain() {
	defer c.wg.Done()
	for ev := range c.queue {
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.HTTPTimeout*4)
		if err := c.EmitWORM(ctx, ev); err != nil {
			c.logger.Warn().Err(err).Str("event_type", ev.EventType).Msg("WORM emit failed")
		}
		cancel()
		if c.metrics != nil {
			c.metrics.SetCitadelQueueDepth(len(c.queue))
		}
	}
}

// Close stops accepting new events and waits up to 10s for the queue
// to drain.
func (c *Client) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	close(c.queue)
	c.closeMu.Unlock()

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("citadel: drain timeout")
	}
}
