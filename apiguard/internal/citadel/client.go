package citadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is a fire-and-forget CITADEL HTTP API client.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New creates a CITADEL client. When baseURL is empty the client is a no-op.
func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 2 * time.Second},
	}
}

// LogEvent forwards an audit event to CITADEL. It runs in its own goroutine so
// it never blocks the caller. All errors are silently discarded — CITADEL
// forwarding is best-effort.
func (c *Client) LogEvent(
	actionType, actorUserID, actorRole, resultStatus, systemModule, resourceID string,
	metadata map[string]interface{},
) {
	if c == nil || c.baseURL == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.logEvent(ctx, actionType, actorUserID, actorRole, resultStatus, systemModule, resourceID, metadata)
	}()
}

func (c *Client) logEvent(
	ctx context.Context,
	actionType, actorUserID, actorRole, resultStatus, systemModule, resourceID string,
	metadata map[string]interface{},
) error {
	payload := map[string]interface{}{
		"action_type":   actionType,
		"actor_user_id": actorUserID,
		"actor_role":    actorRole,
		"result_status": resultStatus,
		"system_module": systemModule,
		"resource_id":   resourceID,
		"metadata":      metadata,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("citadel: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/log", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("citadel: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("citadel: POST /v1/log: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("citadel: POST /v1/log returned status %d", resp.StatusCode)
	}
	return nil
}
