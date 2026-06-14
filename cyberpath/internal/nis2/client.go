// Package nis2 — outbound HTTP client.
//
// HMAC scheme matches CITADEL: signed input is timestamp + "." + body,
// HMAC-SHA256, hex-encoded, sent in X-CyberPath-Signature with the
// timestamp in X-CyberPath-Timestamp.
//
// Body canonicalisation: the JSON bytes produced by encoding/json's
// Marshal of the request struct are signed and sent verbatim. Field
// ordering follows struct declaration order (encoding/json is
// deterministic for a given struct), so the same input always
// produces the same on-wire bytes — that is the canonical form.
//
// Failures are logged but never crash the caller: NIS2 Compass is a
// best-effort dependency. Callers receive an error and can degrade
// gracefully (the handler returns its own coverage view, the
// recommend endpoint returns an empty list, etc.).
//
// Wire in cmd/server/main.go via Options.NIS2Client.
package nis2

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

	"github.com/rs/zerolog"
)

// Options configures the Client.
type Options struct {
	BaseURL       string
	HMACSecret    string
	SecretVersion string
	HTTPTimeout   time.Duration
	MaxRetries    int
	Logger        zerolog.Logger
}

// Client is safe for concurrent use.
type Client struct {
	baseURL       string
	hmacSecret    string
	secretVersion string
	maxRetries    int
	http          *http.Client
	logger        zerolog.Logger
}

// New constructs a Client with sensible defaults.
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
		baseURL:       opts.BaseURL,
		hmacSecret:    opts.HMACSecret,
		secretVersion: opts.SecretVersion,
		maxRetries:    retries,
		http:          &http.Client{Timeout: to},
		logger:        opts.Logger.With().Str("component", "nis2").Logger(),
	}
}

// RecommendTracks POSTs the gap to NIS2 Compass /api/v1/recommend and
// returns the recommended tracks.
func (c *Client) RecommendTracks(ctx context.Context, tenant string, gap GapID) ([]TrackRecommendation, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("nis2/recommend: base URL not configured")
	}
	body, err := canonicalJSON(recommendRequest{Tenant: tenant, Gap: gap})
	if err != nil {
		return nil, fmt.Errorf("nis2/recommend: marshal: %w", err)
	}
	resp, err := c.doSigned(ctx, http.MethodPost, "/api/v1/recommend", body)
	if err != nil {
		return nil, fmt.Errorf("nis2/recommend: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("nis2/recommend: status %d: %s", resp.StatusCode, string(respBytes))
	}
	var out recommendResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("nis2/recommend: decode: %w", err)
	}
	return out.Recommendations, nil
}

// ReportCoverage pushes coverage data to NIS2 Compass for
// cross-platform aggregation.
func (c *Client) ReportCoverage(ctx context.Context, report CoverageReport) error {
	if c.baseURL == "" {
		return fmt.Errorf("nis2/coverage: base URL not configured")
	}
	body, err := canonicalJSON(report)
	if err != nil {
		return fmt.Errorf("nis2/coverage: marshal: %w", err)
	}
	resp, err := c.doSigned(ctx, http.MethodPost, "/api/v1/coverage", body)
	if err != nil {
		return fmt.Errorf("nis2/coverage: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("nis2/coverage: status %d: %s", resp.StatusCode, string(respBytes))
	}
	return nil
}

// Health probes /healthz. Used by /readyz.
func (c *Client) Health(ctx context.Context) (bool, error) {
	if c.baseURL == "" {
		return false, fmt.Errorf("nis2/health: base URL not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return false, fmt.Errorf("nis2/health: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("nis2/health: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// doSigned issues an HMAC-signed request and applies the retry policy:
// exponential backoff on 5xx and transport errors, no retry on 4xx.
func (c *Client) doSigned(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
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
		req.Header.Set("X-CyberPath-Timestamp", ts)
		req.Header.Set("X-CyberPath-Signature", "sha256="+sign(body, ts, c.hmacSecret))
		if c.secretVersion != "" {
			req.Header.Set("X-CyberPath-Secret-Version", c.secretVersion)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			c.logger.Warn().Err(err).Int("attempt", attempt).Msg("nis2 transport error; will retry")
			continue
		}
		if resp.StatusCode >= 500 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
			c.logger.Warn().Int("status", resp.StatusCode).Int("attempt", attempt).Msg("nis2 5xx; will retry")
			continue
		}
		// 2xx and 4xx: return without retry.
		return resp, nil
	}
	return nil, lastErr
}

// canonicalJSON returns the bytes used both on the wire and for HMAC
// signing. encoding/json's output is deterministic for a given struct
// (field order = declaration order), which is the contract here.
func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// sign computes HMAC-SHA256 over (timestamp || "." || body), hex.
func sign(body []byte, timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
