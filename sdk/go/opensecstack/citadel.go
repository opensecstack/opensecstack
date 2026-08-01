package opensecstack

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SecurityEvent is a structured audit event delivered to the CITADEL governance
// platform by APIGuard or NIS2 Compass. Events are chained together via
// SHA-256 hash links to form a tamper-evident WORM audit log.
type SecurityEvent struct {
	ID           string          `json:"id"`
	EventType    string          `json:"event_type"`    // e.g. "apiguard.scan.completed"
	Source       string          `json:"source"`        // "apiguard" | "nis2compass"
	ActorID      string          `json:"actor_id"`
	ActorType    string          `json:"actor_type"`    // "api_key" | "system"
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Severity     string          `json:"severity"`      // "info" | "warning" | "critical"
	Payload      json.RawMessage `json:"payload"`
	PrevHash     *string         `json:"prev_hash,omitempty"`
	ChainHash    string          `json:"chain_hash"`
	Timestamp    time.Time       `json:"timestamp"`
}

// GetEventsOptions holds optional filter and pagination parameters for GetEvents.
type GetEventsOptions struct {
	// Source filters events by originating platform ("apiguard", "nis2compass").
	Source string
	// EventType filters by event type string (e.g. "apiguard.scan.completed").
	EventType string
	// Since returns only events at or after this time.
	Since *time.Time
	// Until returns only events at or before this time.
	Until *time.Time
	// Limit is the maximum number of events to return (server default when 0).
	Limit int
	// Page is the 1-based page number (server default 1 when 0).
	Page int
}

// CITADELClientOptions configures the CITADEL client.
type CITADELClientOptions struct {
	// BaseURL is the root URL of the CITADEL instance (no trailing slash).
	// An empty BaseURL puts the client in no-op mode: all calls return nil immediately.
	BaseURL string
	// SharedSecret is the HMAC-SHA256 signing key used for webhook authentication.
	SharedSecret string
	// MaxRetries is the maximum number of retry attempts for transient 5xx errors.
	// Defaults to 3 when zero.
	MaxRetries int
	// RetryWaitBase is the base duration for exponential backoff between retries.
	// Defaults to 500ms when zero.
	RetryWaitBase time.Duration
	// HTTPClient is the underlying HTTP client. A default 30-second-timeout client
	// is used when nil.
	HTTPClient *http.Client
}

// CITADELClient sends structured security events to the CITADEL governance platform
// and queries its immutable audit chain.
//
// Events are delivered via HMAC-SHA256 signed HTTP POST. The client handles
// authentication, signing, retry, and WORM chain verification automatically.
//
// Non-blocking delivery: SendEvent queues the event on an internal buffered channel
// and returns immediately. A background worker goroutine performs the actual HTTP
// delivery with exponential-backoff retry, then discards on final failure rather
// than blocking the caller.
//
// Disabled mode: if BaseURL is empty the client is disabled and all methods return
// nil immediately without performing any I/O.
type CITADELClient struct {
	baseURL       string
	sharedSecret  []byte
	httpClient    *http.Client
	maxRetries    int
	retryWaitBase time.Duration

	// eventCh is the internal dispatch channel for non-blocking SendEvent.
	eventCh chan SecurityEvent
	// wg tracks in-flight background deliveries so Drain can wait for them.
	wg sync.WaitGroup
	// once guards start-up of the background worker.
	once sync.Once
	// stopCh is closed by Drain to signal the worker to shut down cleanly.
	stopCh chan struct{}
}

// NewCITADELClient creates a new client with the given options.
//
// If opts.BaseURL is empty the client is disabled and all operations are no-ops.
func NewCITADELClient(opts CITADELClientOptions) *CITADELClient {
	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	retryWait := opts.RetryWaitBase
	if retryWait <= 0 {
		retryWait = 500 * time.Millisecond
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	c := &CITADELClient{
		baseURL:       strings.TrimRight(opts.BaseURL, "/"),
		sharedSecret:  []byte(opts.SharedSecret),
		httpClient:    httpClient,
		maxRetries:    maxRetries,
		retryWaitBase: retryWait,
		eventCh:       make(chan SecurityEvent, 256),
		stopCh:        make(chan struct{}),
	}

	// Start the background dispatch worker immediately so callers can send events
	// before any explicit action. The worker is a no-op when BaseURL is empty.
	if opts.BaseURL != "" {
		c.once.Do(func() { go c.dispatchWorker() })
	}

	return c
}

// citadelURL builds an absolute API URL for the given path.
func (c *CITADELClient) citadelURL(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.baseURL, strings.TrimLeft(path, "/"))
}

// signBody computes HMAC-SHA256 over body and returns "sha256=<hex>" ready to
// place in the X-Citadel-Signature header.
func (c *CITADELClient) signBody(body []byte) string {
	mac := hmac.New(sha256.New, c.sharedSecret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// dispatchWorker reads events from c.eventCh and delivers them to CITADEL with
// exponential-backoff retry. It exits when c.stopCh is closed and the channel
// is drained.
func (c *CITADELClient) dispatchWorker() {
	for {
		select {
		case event, ok := <-c.eventCh:
			if !ok {
				return
			}
			c.wg.Add(1)
			go func(ev SecurityEvent) {
				defer c.wg.Done()
				if err := c.deliverEvent(context.Background(), ev); err != nil {
					slog.Error("citadel: event delivery failed after retries",
						"event_id", ev.ID,
						"event_type", ev.EventType,
						"error", err,
					)
				}
			}(event)
		case <-c.stopCh:
			// Drain remaining events.
			for {
				select {
				case event, ok := <-c.eventCh:
					if !ok {
						return
					}
					c.wg.Add(1)
					go func(ev SecurityEvent) {
						defer c.wg.Done()
						if err := c.deliverEvent(context.Background(), ev); err != nil {
							slog.Error("citadel: event delivery failed during drain",
								"event_id", ev.ID,
								"error", err,
							)
						}
					}(event)
				default:
					return
				}
			}
		}
	}
}

// deliverEvent performs the actual HTTP delivery of a SecurityEvent with retry.
func (c *CITADELClient) deliverEvent(ctx context.Context, event SecurityEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("citadel: marshalling event: %w", err)
	}
	sig := c.signBody(body)

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.retryWaitBase * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.citadelURL("events"), bytes.NewReader(body))
		if err != nil {
			lastErr = fmt.Errorf("building request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Citadel-Signature", sig)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request: %w", err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode < 500 {
			// 4xx errors are not retried — give up immediately.
			return fmt.Errorf("CITADEL returned HTTP %d (not retried)", resp.StatusCode)
		}
		lastErr = fmt.Errorf("CITADEL returned HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("citadel: max retries exceeded: %w", lastErr)
}

// SendEvent delivers a SecurityEvent to CITADEL.
//
// The call is non-blocking: the event is placed on an internal queue and the
// actual HTTP delivery (with retry) happens in a background goroutine. The caller
// receives an error only if the queue is full, which indicates severe back-pressure.
//
// If BaseURL is empty (disabled mode), the call is a no-op and returns nil.
func (c *CITADELClient) SendEvent(ctx context.Context, event SecurityEvent) error {
	if c.baseURL == "" {
		return nil
	}
	select {
	case c.eventCh <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("citadel: event queue is full; event %s dropped", event.ID)
	}
}

// GetEvents queries the CITADEL audit chain with optional filters.
//
// If BaseURL is empty, returns an empty slice and nil.
func (c *CITADELClient) GetEvents(ctx context.Context, opts GetEventsOptions) ([]SecurityEvent, error) {
	if c.baseURL == "" {
		return nil, nil
	}

	params := url.Values{}
	if opts.Source != "" {
		params.Set("source", opts.Source)
	}
	if opts.EventType != "" {
		params.Set("event_type", opts.EventType)
	}
	if opts.Since != nil {
		params.Set("since", opts.Since.UTC().Format(time.RFC3339))
	}
	if opts.Until != nil {
		params.Set("until", opts.Until.UTC().Format(time.RFC3339))
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Page > 0 {
		params.Set("page", strconv.Itoa(opts.Page))
	}

	apiPath := "events"
	if len(params) > 0 {
		apiPath += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.citadelURL(apiPath), nil)
	if err != nil {
		return nil, fmt.Errorf("GetEvents: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetEvents: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GetEvents: reading body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GetEvents: CITADEL returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	// Support both a plain array and a paginated envelope {"items": [...]}
	var events []SecurityEvent
	if err := json.Unmarshal(raw, &events); err == nil {
		return events, nil
	}
	var envelope struct {
		Items []SecurityEvent `json:"items"`
		Data  []SecurityEvent `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("GetEvents: unexpected response format: %w", err)
	}
	if envelope.Items != nil {
		return envelope.Items, nil
	}
	return envelope.Data, nil
}

// GetEvent fetches a single SecurityEvent by ID.
//
// If BaseURL is empty, returns nil and nil.
func (c *CITADELClient) GetEvent(ctx context.Context, eventID string) (*SecurityEvent, error) {
	if c.baseURL == "" {
		return nil, nil
	}
	if eventID == "" {
		return nil, fmt.Errorf("GetEvent: eventID must not be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.citadelURL("events/"+eventID), nil)
	if err != nil {
		return nil, fmt.Errorf("GetEvent: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetEvent %s: %w", eventID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GetEvent %s: reading body: %w", eventID, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GetEvent %s: event not found", eventID)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GetEvent %s: CITADEL returned HTTP %d: %s", eventID, resp.StatusCode, string(raw))
	}

	var event SecurityEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("GetEvent %s: decoding response: %w", eventID, err)
	}
	return &event, nil
}

// VerifyChain verifies that a contiguous slice of SecurityEvents forms a valid
// SHA-256 hash chain.
//
// For each consecutive pair (events[i], events[i+1]) the function recomputes:
//
//	SHA-256(events[i].ChainHash + events[i+1].Payload)
//
// and checks that the result matches events[i+1].ChainHash. An error is returned
// for the first broken link, including the zero-based index of the offending event.
//
// Returns nil for slices of 0 or 1 events (no links to verify).
func (c *CITADELClient) VerifyChain(_ context.Context, events []SecurityEvent) error {
	if len(events) < 2 {
		return nil
	}
	for i := 0; i < len(events)-1; i++ {
		prev := events[i]
		next := events[i+1]

		h := sha256.New()
		h.Write([]byte(prev.ChainHash))
		h.Write(next.Payload)
		computed := hex.EncodeToString(h.Sum(nil))

		if computed != next.ChainHash {
			return fmt.Errorf(
				"VerifyChain: broken link at index %d → %d: "+
					"expected chain_hash %q, computed %q "+
					"(event_ids: %q → %q)",
				i, i+1,
				next.ChainHash, computed,
				prev.ID, next.ID,
			)
		}
	}
	return nil
}

// Drain flushes any buffered events and waits for all in-flight deliveries to
// complete. It should be called on graceful shutdown with a context deadline.
//
// After Drain returns the client must not be used to send further events.
func (c *CITADELClient) Drain(ctx context.Context) error {
	if c.baseURL == "" {
		return nil
	}

	// Signal the dispatch worker to stop accepting new events and flush.
	close(c.stopCh)

	// Wait for all in-flight goroutines to finish, respecting the deadline.
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("citadel: Drain timed out waiting for in-flight events: %w", ctx.Err())
	}
}
