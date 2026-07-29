package citadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client submits Kerkese governance requests to a CITADEL instance's MARSHAL
// engine and registers Ed25519 signing keys.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Client for the CITADEL instance at baseURL (no
// trailing slash required). A nil httpClient defaults to a 30s timeout.
func NewClient(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}
}

func (c *Client) url(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.baseURL, strings.TrimLeft(path, "/"))
}

// Evaluate submits a Kerkese to POST /api/v1/marshal/evaluate and returns
// MARSHAL's Decision. The caller must have already populated
// SigOperator/SigVerifier via Sign if the target instance enforces
// signatures (citadel ADR-004).
//
// CITADEL returns HTTP 403 for REFUSE and HARD_STOP outcomes — that is a
// well-formed Decision, not a transport error, and callers need
// Decision.Reasons to surface why an action was blocked. Only a response
// body that fails to parse as a Decision at all is treated as an error.
func (c *Client) Evaluate(ctx context.Context, k Kerkese) (*Decision, error) {
	body, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("citadel: Evaluate: marshalling Kerkese: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("marshal/evaluate"), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("citadel: Evaluate: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("citadel: Evaluate: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("citadel: Evaluate: reading response: %w", err)
	}

	var decision Decision
	if err := json.Unmarshal(raw, &decision); err != nil {
		// Not a parseable Decision — a genuine transport/server failure
		// (5xx with a plain-text body, proxy error page, etc.), not a
		// REFUSE/HARD_STOP business outcome.
		return nil, fmt.Errorf("citadel: Evaluate: HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if decision.Outcome == "" {
		// Parsed as valid JSON but not actually a Decision (e.g. an error
		// envelope like {"error": "..."}) — still treat as a failure.
		return nil, fmt.Errorf("citadel: Evaluate: HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return &decision, nil
}

// KeyRegistration is the body sent to POST /api/v1/keys/register.
type KeyRegistration struct {
	UserID    int64  `json:"user_id"`
	SessionID string `json:"session_id"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // hex, 64 chars
}

// KeyRegistrationResponse is returned on successful registration.
type KeyRegistrationResponse struct {
	KeyID        string    `json:"key_id"`
	RegisteredAt time.Time `json:"registered_at"`
}

// RegisterKey binds an Ed25519 public key to user_id, authenticated by the
// caller's existing CITADEL session (session_id must belong to user_id, or
// the server returns 403 — see citadel/internal/api/handlers/keys.go).
func (c *Client) RegisterKey(ctx context.Context, reg KeyRegistration) (*KeyRegistrationResponse, error) {
	body, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("citadel: RegisterKey: marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("keys/register"), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("citadel: RegisterKey: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("citadel: RegisterKey: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("citadel: RegisterKey: reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("citadel: RegisterKey: HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var out KeyRegistrationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("citadel: RegisterKey: decoding response: %w", err)
	}
	return &out, nil
}
