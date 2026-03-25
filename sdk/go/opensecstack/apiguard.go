package opensecstack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIGuardClient is an HTTP client for the APIGuard platform API.
//
// Authentication uses a two-step flow: the APIKey is exchanged for a
// short-lived JWT via POST /api/v1/auth/token. The JWT is cached and
// refreshed automatically on expiry (HTTP 401).
type APIGuardClient struct {
	// BaseURL is the root URL of the APIGuard instance (no trailing slash).
	BaseURL string
	// APIKey is the pre-shared key used to obtain JWTs.
	APIKey string
	// HTTPClient is the underlying HTTP client. A default client with a
	// 30-second timeout is used when nil.
	HTTPClient *http.Client

	mu  sync.Mutex
	jwt string // cached Bearer token; empty means unauthenticated
}

// NewAPIGuardClient creates an APIGuardClient with sensible defaults.
func NewAPIGuardClient(baseURL, apiKey string) *APIGuardClient {
	return &APIGuardClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

func (c *APIGuardClient) apiURL(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.BaseURL, strings.TrimLeft(path, "/"))
}

// authenticate exchanges the API key for a JWT and caches it.
// Must be called with c.mu held or before the first request.
func (c *APIGuardClient) authenticate(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"api_key": c.APIKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL("auth/token"), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid API key")
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth error HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding auth response: %w", err)
	}
	token, _ := data["access_token"].(string)
	if token == "" {
		token, _ = data["token"].(string)
	}
	if token == "" {
		return fmt.Errorf("no access_token in auth response")
	}
	c.jwt = token
	return nil
}

// do executes an HTTP request with the JWT Bearer token, re-authenticating
// once on HTTP 401.
//
// The body is buffered into memory so that it can be replayed intact if the
// first attempt returns 401 and a token refresh is required.
func (c *APIGuardClient) do(ctx context.Context, method, path string, body io.Reader, extraHeaders map[string]string) (*http.Response, error) {
	// Buffer body for replay on token-refresh retry.
	var bodyBuf []byte
	if body != nil {
		var err error
		bodyBuf, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}
	}

	c.mu.Lock()
	if c.jwt == "" {
		if err := c.authenticate(ctx); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}
	jwt := c.jwt
	c.mu.Unlock()

	newReader := func() io.Reader {
		if bodyBuf != nil {
			return bytes.NewReader(bodyBuf)
		}
		return nil
	}

	resp, err := c.doWithJWT(ctx, method, path, newReader(), jwt, extraHeaders)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		// Token may have expired — re-authenticate once.
		c.mu.Lock()
		if err := c.authenticate(ctx); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		jwt = c.jwt
		c.mu.Unlock()
		resp, err = c.doWithJWT(ctx, method, path, newReader(), jwt, extraHeaders)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (c *APIGuardClient) doWithJWT(ctx context.Context, method, path string, body io.Reader, jwt string, extraHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return c.HTTPClient.Do(req)
}

// checkResponse reads the response body and returns a decoded error when the
// status code is >= 400. On success it returns the raw body for the caller to
// decode.
func checkResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode >= 400 {
		var ae apiError
		if jsonErr := json.Unmarshal(raw, &ae); jsonErr == nil && (ae.Error != "" || ae.Message != "") {
			return nil, fmt.Errorf("API error HTTP %d: %s — %s", resp.StatusCode, ae.Error, ae.Message)
		}
		return nil, fmt.Errorf("API error HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func (c *APIGuardClient) getJSON(ctx context.Context, path string, params url.Values, out interface{}) error {
	fullPath := path
	if len(params) > 0 {
		fullPath = path + "?" + params.Encode()
	}
	resp, err := c.do(ctx, http.MethodGet, fullPath, nil, nil)
	if err != nil {
		return err
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (c *APIGuardClient) postJSON(ctx context.Context, path string, reqBody interface{}, out interface{}) error {
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encoding request body: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, path, bytes.NewReader(encoded),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (c *APIGuardClient) patchJSON(ctx context.Context, path string, reqBody interface{}, out interface{}) error {
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encoding request body: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPatch, path, bytes.NewReader(encoded),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

// CreateScan submits a new scan to APIGuard.
//
// Provide either specURL (a publicly reachable OpenAPI spec URL) or
// specPath (a server-side path returned by the spec upload endpoint).
// target is the base URL of the API under test; when empty and specURL
// is set, the host of specURL is used.
//
// The server starts the scan asynchronously and immediately returns a
// pending Scan record. Poll GetScan until Status is "completed" or "failed".
func (c *APIGuardClient) CreateScan(ctx context.Context, specURL string) (*Scan, error) {
	return c.CreateScanFull(ctx, CreateScanOptions{SpecURL: specURL})
}

// CreateScanOptions exposes the full set of POST /api/v1/scans parameters.
type CreateScanOptions struct {
	SpecURL    string
	SpecPath   string
	Target     string
	Modules    []string
	AuthType   string
	AuthToken  string
	AuthHeader string
}

// CreateScanFull submits a new scan with full option control.
func (c *APIGuardClient) CreateScanFull(ctx context.Context, opts CreateScanOptions) (*Scan, error) {
	if opts.SpecURL == "" && opts.SpecPath == "" {
		return nil, fmt.Errorf("one of SpecURL or SpecPath must be provided")
	}
	target := opts.Target
	if target == "" && opts.SpecURL != "" {
		u, err := url.Parse(opts.SpecURL)
		if err == nil {
			target = u.Scheme + "://" + u.Host
		}
	}
	reqBody := createScanRequest{
		SpecURL:    opts.SpecURL,
		SpecPath:   opts.SpecPath,
		Target:     target,
		Modules:    opts.Modules,
		AuthType:   opts.AuthType,
		AuthToken:  opts.AuthToken,
		AuthHeader: opts.AuthHeader,
	}
	var scan Scan
	if err := c.postJSON(ctx, "scans", reqBody, &scan); err != nil {
		return nil, fmt.Errorf("CreateScan: %w", err)
	}
	return &scan, nil
}

// GetScan retrieves a scan by UUID.
func (c *APIGuardClient) GetScan(ctx context.Context, scanID string) (*Scan, error) {
	var scan Scan
	if err := c.getJSON(ctx, "scans/"+scanID, nil, &scan); err != nil {
		return nil, fmt.Errorf("GetScan %s: %w", scanID, err)
	}
	return &scan, nil
}

// GetFindings returns all findings for a completed scan.
// Results are fetched from GET /api/v1/scans/{id}/findings.
func (c *APIGuardClient) GetFindings(ctx context.Context, scanID string) ([]Finding, error) {
	params := url.Values{}
	params.Set("page", "1")
	params.Set("per_page", strconv.Itoa(1000))

	fullPath := fmt.Sprintf("scans/%s/findings?%s", scanID, params.Encode())
	resp, err := c.do(ctx, http.MethodGet, fullPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("GetFindings %s: %w", scanID, err)
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("GetFindings %s: %w", scanID, err)
	}

	// Try envelope format {"data": [...]} first.
	var envelope findingsResponse
	if jsonErr := json.Unmarshal(raw, &envelope); jsonErr == nil && envelope.Data != nil {
		return envelope.Data, nil
	}

	// Fall back to plain array.
	var findings []Finding
	if jsonErr := json.Unmarshal(raw, &findings); jsonErr != nil {
		return nil, fmt.Errorf("GetFindings %s: unexpected response format: %w", scanID, jsonErr)
	}
	return findings, nil
}

// PatchFinding triages a single finding by updating its status and optional note.
// id is the UUID of the finding to update. Status must be one of:
// "open", "confirmed", "false_positive", "accepted", "fixed".
func (c *APIGuardClient) PatchFinding(ctx context.Context, id string, req PatchFindingRequest) (*Finding, error) {
	var finding Finding
	if err := c.patchJSON(ctx, "findings/"+id, req, &finding); err != nil {
		return nil, fmt.Errorf("PatchFinding %s: %w", id, err)
	}
	return &finding, nil
}

// GetAuditLog retrieves the most recent audit log entries (up to limit).
func (c *APIGuardClient) GetAuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	params := url.Values{}
	params.Set("per_page", strconv.Itoa(limit))

	var entries []AuditEntry
	if err := c.getJSON(ctx, "audit", params, &entries); err != nil {
		return nil, fmt.Errorf("GetAuditLog: %w", err)
	}
	return entries, nil
}
