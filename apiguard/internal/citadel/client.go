package citadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client is a fire-and-forget CITADEL HTTP API client.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	wg      sync.WaitGroup
}

// New creates a CITADEL client. When baseURL is empty the client is a no-op.
func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 10 * time.Second},
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
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.logEvent(ctx, actionType, actorUserID, actorRole, resultStatus, systemModule, resourceID, metadata)
	}()
}

// Drain waits for all in-flight LogEvent goroutines to finish, or until ctx is
// cancelled. It is safe to call on a nil Client.
func (c *Client) Drain(ctx context.Context) {
	if c == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (c *Client) logEvent(
	ctx context.Context,
	actionType, actorUserID, actorRole, resultStatus, systemModule, resourceID string,
	metadata map[string]interface{},
) error {
	// CITADEL server expects actor_user_id as an integer. We send 0 as the
	// canonical system/service-account value because APIGuard authenticates
	// with service tokens rather than per-user CITADEL accounts.
	// The real actor identifier (JWT sub) is forwarded in metadata so it is
	// never lost.
	enriched := make(map[string]interface{}, len(metadata)+1)
	for k, v := range metadata {
		enriched[k] = v
	}
	if actorUserID != "" {
		enriched["actor_subject"] = actorUserID
	}
	payload := map[string]interface{}{
		"action_type":   actionType,
		"actor_user_id": 0,
		"actor_role":    actorRole,
		"result_status": resultStatus,
		"system_module": systemModule,
		"resource_id":   resourceID,
		"metadata":      enriched,
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
	// A-L4: consume the body before closing so the underlying TCP connection
	// can be reused by the http.Client's connection pool.
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("citadel: POST /v1/log returned status %d", resp.StatusCode)
	}
	return nil
}
