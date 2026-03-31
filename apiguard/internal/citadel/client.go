package citadel

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
	"strings"
	"sync"
	"time"
)

// Client connects to CITADEL using HMAC-SHA256 connector auth.
// When baseURL is empty every method is a no-op so apiguard runs
// normally when CITADEL is not configured.
type Client struct {
	baseURL string
	keyID   string
	secret  string
	http    *http.Client
	wg      sync.WaitGroup
	sem     chan struct{} // bounded concurrency for LogEvent goroutines
}

// New creates a CITADEL client.
// When baseURL is empty the client is a no-op — all calls return immediately
// without making any network requests.
func New(baseURL, keyID, secret string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		keyID:   keyID,
		secret:  secret,
		http:    &http.Client{Timeout: 10 * time.Second},
		sem:     make(chan struct{}, 64),
	}
}

// EvaluateScan calls POST /api/v1/marshal/evaluate and returns CITADEL's
// governance Decision. The caller must block on REFUSE or HARD_STOP outcomes.
// Returns (nil, nil) when the client is disabled (empty baseURL).
func (c *Client) EvaluateScan(ctx context.Context, k *Kerkese) (*Decision, error) {
	if c == nil || c.baseURL == "" {
		return nil, nil
	}
	body, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("citadel: marshal kerkese: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/marshal/evaluate", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("citadel: POST /api/v1/marshal/evaluate returned status %d", resp.StatusCode)
	}
	var d Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("citadel: decode decision: %w", err)
	}
	return &d, nil
}

// EmitWORM posts an immutable event to POST /api/v1/worm/emit.
// Returns (entryID, chainHash, nil) on success.
// Returns ("", "", nil) when the client is disabled.
func (c *Client) EmitWORM(ctx context.Context, source, eventType, projectID string, payload any) (string, string, error) {
	if c == nil || c.baseURL == "" {
		return "", "", nil
	}
	reqBody := map[string]any{
		"source":     source,
		"event_type": eventType,
		"project_id": projectID,
		"payload":    payload,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("citadel: marshal worm payload: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/worm/emit", body)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("citadel: POST /api/v1/worm/emit returned status %d", resp.StatusCode)
	}
	var result struct {
		WORMEntryID string `json:"worm_entry_id"`
		ChainHash   string `json:"chain_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("citadel: decode worm response: %w", err)
	}
	return result.WORMEntryID, result.ChainHash, nil
}

// LogEvent emits a WORM event in a background goroutine (fire-and-forget).
// Errors are silently discarded — CITADEL forwarding is best-effort.
// Called from the audit log worker for each local audit entry.
func (c *Client) LogEvent(
	actionType, actorUserID, actorRole, resultStatus, systemModule, resourceID string,
	metadata map[string]interface{},
) {
	if c == nil || c.baseURL == "" {
		return
	}
	payload := map[string]interface{}{
		"action_type":   actionType,
		"actor_user_id": actorUserID,
		"actor_role":    actorRole,
		"result_status": resultStatus,
		"system_module": systemModule,
		"resource_id":   resourceID,
	}
	for k, v := range metadata {
		payload[k] = v
	}
	select {
	case c.sem <- struct{}{}:
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { <-c.sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _, _ = c.EmitWORM(ctx, systemModule, actionType, "apiguard", payload)
		}()
	default:
		// semaphore full — drop event (best-effort, bounded goroutine count)
	}
}

// Drain waits for all in-flight LogEvent goroutines to finish, or until ctx
// is cancelled. Safe to call on a nil Client.
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

// do performs a signed HTTP request to CITADEL.
// Every request carries three HMAC-SHA256 connector-auth headers:
//
//	X-CITADEL-KEY  — the connector key ID
//	X-CITADEL-TS   — current Unix timestamp (seconds)
//	X-CITADEL-SIG  — hmac-sha256=hex(HMAC-SHA256(secret, key_id+":"+ts+":"+hex(sha256(body))))
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("citadel: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	bodyHash := sha256.Sum256(body)
	message := c.keyID + ":" + ts + ":" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write([]byte(message))
	sig := "hmac-sha256=" + hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-CITADEL-KEY", c.keyID)
	req.Header.Set("X-CITADEL-TS", ts)
	req.Header.Set("X-CITADEL-SIG", sig)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("citadel: %s %s: %w", method, path, err)
	}
	return resp, nil
}
