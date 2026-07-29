// Package nis2 — minimal outbound connectivity client for NIS2 Compass.
//
// Per ADR-014 (adrs/ADR-014-cyberpath-nis2compass-integration-direction.md),
// the accepted integration direction is PULL: NIS2 Compass calls
// CyberPath's GET /api/v1/coverage/{user_id} and
// GET /api/v1/cyberpath/recommend?gap=<measure> endpoints (see
// internal/api/handlers/coverage.go and docs/api.md). CyberPath never
// pushes data to NIS2 Compass, so this package no longer implements an
// outbound POST client, the X-CyberPath-Signature/X-CyberPath-Timestamp
// HMAC scheme, or retry/backoff for push calls — those endpoints never
// existed on the NIS2 Compass side (see the ADR for the investigation).
//
// What remains is a small health-check client used to report NIS2
// Compass reachability from CyberPath's own /readyz endpoint
// (docs/api.md's `integrations.nis2compass` field) — a legitimate,
// still-needed connectivity check that is independent of the
// push/pull direction question.
//
// Wire in cmd/server/main.go via Options.NIS2Client.
package nis2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// Options configures the Client.
type Options struct {
	BaseURL     string
	HTTPTimeout time.Duration
	Logger      zerolog.Logger
}

// Client is safe for concurrent use.
type Client struct {
	baseURL string
	http    *http.Client
	logger  zerolog.Logger
}

// New constructs a Client with sensible defaults.
func New(opts Options) *Client {
	to := opts.HTTPTimeout
	if to <= 0 {
		to = 5 * time.Second
	}
	return &Client{
		baseURL: opts.BaseURL,
		http:    &http.Client{Timeout: to},
		logger:  opts.Logger.With().Str("component", "nis2").Logger(),
	}
}

// Health probes NIS2 Compass's /healthz. Used by CyberPath's own
// /readyz to report nis2compass connectivity.
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
