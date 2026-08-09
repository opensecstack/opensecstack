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
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FailMode decides what EvaluateScan returns when CITADEL itself cannot be
// reached or returns an unparseable response — i.e. when governance can't
// be evaluated at all, as distinct from CITADEL evaluating the request and
// returning REFUSE/HARD_STOP. FailClosed (the zero value) is the safe
// default: an unreachable CITADEL blocks the scan rather than letting it
// proceed ungoverned.
type FailMode int

const (
	// FailClosed treats an unreachable CITADEL as HARD_STOP. Safe
	// default; the zero value.
	FailClosed FailMode = iota
	// FailOpen treats an unreachable CITADEL as EXECUTE. Only set this
	// deliberately, and document why at the call site.
	FailOpen
)

// Client connects to CITADEL using HMAC-SHA256 connector auth.
// When baseURL is empty every method is a no-op so apiguard runs
// normally when CITADEL is not configured.
type Client struct {
	baseURL       string
	keyID         string
	secret        string
	http          *http.Client
	wg            sync.WaitGroup
	sem           chan struct{} // bounded concurrency for LogEvent goroutines
	maxRetries    int           // maximum retry attempts on 5xx / network errors (default 3)
	retryWaitBase time.Duration // base wait for exponential backoff (default 500ms)

	// FailMode governs EvaluateScan's behavior when CITADEL is
	// unreachable. Defaults to FailClosed (the zero value).
	FailMode FailMode

	// Chain anchor verification state
	mu            sync.Mutex // protects lastChainHash
	lastChainHash string     // chain_hash from the most recent EmitWORM response
	logger        Logger
}

// Logger is the interface used by the Client for chain verification warnings.
// Compatible with *log.Logger and most structured loggers.
type Logger interface {
	Printf(format string, v ...any)
}

// defaultLogger wraps the standard log package.
type defaultLogger struct{}

func (defaultLogger) Printf(format string, v ...any) { log.Printf(format, v...) }

// New creates a CITADEL client.
// When baseURL is empty the client is a no-op — all calls return immediately
// without making any network requests.
// Retry defaults: 3 attempts with 500ms exponential backoff base.
func New(baseURL, keyID, secret string) *Client {
	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		keyID:         keyID,
		secret:        secret,
		http:          &http.Client{Timeout: 10 * time.Second},
		sem:           make(chan struct{}, 64),
		maxRetries:    3,
		retryWaitBase: 500 * time.Millisecond,
		logger:        defaultLogger{},
	}
}

// EvaluateScan calls POST /api/v1/marshal/evaluate and returns CITADEL's
// governance Decision. The caller must block on REFUSE or HARD_STOP
// outcomes — decision.Allowed() is the correct way to check this.
// Returns (nil, nil) when the client is disabled (empty baseURL) — callers
// must treat that as "no governance configured", not as an error.
//
// CITADEL returns HTTP 403 for REFUSE and HARD_STOP outcomes — that is a
// well-formed Decision, not a transport error; only a response body that
// fails to parse as a Decision at all is treated as an error. This always
// returns a non-nil Decision alongside a non-nil error too (except when
// the client is disabled): on transport failure, the returned Decision is
// synthesized per c.FailMode (HARD_STOP by default), so a caller checking
// decision.Allowed() without also branching on err still gets the safe
// behavior. Check err separately to log/alert on "couldn't evaluate" vs.
// "evaluated and refused."
func (c *Client) EvaluateScan(ctx context.Context, k *Kerkese) (*Decision, error) {
	if c == nil || c.baseURL == "" {
		return nil, nil
	}
	decision, err := c.evaluateScan(ctx, k)
	if err != nil {
		return c.failModeDecision(k, err), err
	}
	return decision, nil
}

func (c *Client) evaluateScan(ctx context.Context, k *Kerkese) (*Decision, error) {
	body, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("citadel: marshal kerkese: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/marshal/evaluate", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }() //nolint:errcheck // best-effort drain to allow connection reuse

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("citadel: read decision response: %w", err)
	}

	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		// Not a parseable Decision — a genuine transport/server failure
		// (5xx with a plain-text body, proxy error page, etc.), not a
		// REFUSE/HARD_STOP business outcome.
		return nil, fmt.Errorf("citadel: POST /api/v1/marshal/evaluate: HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if d.Outcome == "" {
		// Parsed as valid JSON but not actually a Decision.
		return nil, fmt.Errorf("citadel: POST /api/v1/marshal/evaluate: HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return &d, nil
}

// failModeDecision synthesizes the Decision EvaluateScan returns alongside
// a non-nil error, per c.FailMode.
func (c *Client) failModeDecision(k *Kerkese, cause error) *Decision {
	outcome := OutcomeHardStop
	reason := fmt.Sprintf("citadel: MARSHAL unreachable, failing closed (HARD_STOP): %v", cause)
	if c.FailMode == FailOpen {
		outcome = OutcomeExecute
		reason = fmt.Sprintf("citadel: MARSHAL unreachable, failing open (EXECUTE) per configured FailMode: %v", cause)
	}
	d := &Decision{
		Outcome: outcome,
		Reasons: []string{reason},
		TsUTC:   time.Now().UTC(),
	}
	if k != nil {
		d.ExecutionID = k.ExecutionID
	}
	return d
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
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }() //nolint:errcheck // best-effort drain to allow connection reuse

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("citadel: POST /api/v1/worm/emit returned status %d", resp.StatusCode)
	}
	var result struct {
		WORMEntryID string `json:"worm_entry_id"`
		ChainHash   string `json:"chain_hash"`
		PrevHash    string `json:"prev_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("citadel: decode worm response: %w", err)
	}

	// Verify chain continuity: the returned prev_hash should match our
	// stored lastChainHash from the previous EmitWORM call.
	c.mu.Lock()
	if c.lastChainHash != "" && result.PrevHash != "" && result.PrevHash != c.lastChainHash {
		c.logger.Printf("citadel: WORM chain break detected — expected prev_hash %q, got %q (entry %s)",
			c.lastChainHash, result.PrevHash, result.WORMEntryID)
	}
	c.lastChainHash = result.ChainHash
	c.mu.Unlock()

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
			_, _, _ = c.EmitWORM(ctx, systemModule, actionType, "apiguard", payload) //nolint:errcheck // fire-and-forget async audit emission, already bounded/best-effort per comment below
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

// VerifyChain calls CITADEL's chain verification endpoint to check WORM log
// integrity for the given time range.
// GET /api/v1/worm/verify?from=<RFC3339>&to=<RFC3339>
// Returns (nil, nil) when the client is disabled.
func (c *Client) VerifyChain(ctx context.Context, from, to time.Time) (*VerifyResult, error) {
	if c == nil || c.baseURL == "" {
		return nil, nil
	}
	params := url.Values{}
	params.Set("from", from.UTC().Format(time.RFC3339))
	params.Set("to", to.UTC().Format(time.RFC3339))

	resp, err := c.do(ctx, http.MethodGet, "/api/v1/worm/verify?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }() //nolint:errcheck // best-effort drain to allow connection reuse

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("citadel: GET /api/v1/worm/verify returned status %d", resp.StatusCode)
	}
	var result VerifyResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("citadel: decode verify response: %w", err)
	}
	return &result, nil
}

// do performs a signed HTTP request to CITADEL with exponential-backoff retry
// on 5xx and network/timeout errors. 4xx responses are returned immediately
// (client errors are not retried). 2xx responses are returned on success.
//
// Every request carries three HMAC-SHA256 connector-auth headers:
//
//	X-CITADEL-KEY  — the connector key ID
//	X-CITADEL-TS   — current Unix timestamp (seconds)
//	X-CITADEL-SIG  — hmac-sha256=hex(HMAC-SHA256(secret, key_id+":"+ts+":"+hex(sha256(body))))
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// Exponential backoff before retry attempts (not before the first attempt).
		if attempt > 0 {
			wait := c.retryWaitBase * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("citadel: %s %s: context cancelled during retry backoff: %w", method, path, ctx.Err())
			case <-time.After(wait):
			}
		}

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
			// Network or timeout error — retryable.
			lastErr = fmt.Errorf("citadel: %s %s: %w", method, path, err)
			continue
		}

		// 2xx — success, return immediately.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		// 4xx — client error, not retryable. Return response for caller to inspect.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, nil
		}

		// 5xx — server error, retryable. Drain and close the body before retrying.
		_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // best-effort drain to allow connection reuse
		resp.Body.Close()
		lastErr = fmt.Errorf("citadel: %s %s: server returned %d", method, path, resp.StatusCode)
	}

	return nil, fmt.Errorf("citadel: %s %s: max retries (%d) exhausted: %w", method, path, c.maxRetries, lastErr)
}
