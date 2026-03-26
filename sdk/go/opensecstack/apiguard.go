package opensecstack

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	// ReportTimeout is the maximum time to wait for GetReport to complete.
	// When zero, it defaults to 120 seconds (matching the Python SDK).
	ReportTimeout time.Duration

	mu          sync.RWMutex
	jwt         string    // cached Bearer token; empty means unauthenticated
	tokenExpiry time.Time // expiry time parsed from JWT exp claim
}

// NewAPIGuardClient creates an APIGuardClient with sensible defaults.
func NewAPIGuardClient(baseURL, apiKey string) *APIGuardClient {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // do not follow redirects
	}
	return &APIGuardClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     apiKey,
		HTTPClient: httpClient,
	}
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

func (c *APIGuardClient) apiURL(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.BaseURL, strings.TrimLeft(path, "/"))
}

// authenticate exchanges the API key for a JWT and caches it.
// It manages its own locking and must NOT be called with c.mu held.
// It uses double-checked locking so that concurrent callers only issue
// one HTTP request: if the token is already populated when the lock is
// re-acquired after the HTTP round-trip, the fresh token is discarded.
func (c *APIGuardClient) authenticate(ctx context.Context) error {
	// Fast path: check under read lock before making any network call.
	c.mu.RLock()
	hasToken := c.jwt != "" && time.Now().Add(60*time.Second).Before(c.tokenExpiry)
	c.mu.RUnlock()
	if hasToken {
		return nil
	}

	// Make the HTTP call WITHOUT holding the lock.
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

	expiry, err := parseJWTExpiry(token)
	if err != nil {
		// If we cannot parse expiry, use a short default so we still refresh eventually.
		expiry = time.Now().Add(5 * time.Minute)
	}

	// Re-acquire write lock to store the token; double-check that another goroutine
	// did not already populate it while we were doing I/O.
	c.mu.Lock()
	if c.jwt == "" || !time.Now().Add(60*time.Second).Before(c.tokenExpiry) {
		c.jwt = token
		c.tokenExpiry = expiry
	}
	c.mu.Unlock()
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

	// authenticate manages its own locking and must be called without c.mu held.
	if err := c.authenticate(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	jwt := c.jwt
	c.mu.RUnlock()

	newReader := func() io.Reader {
		if bodyBuf != nil {
			return bytes.NewReader(bodyBuf)
		}
		return nil
	}

	doOnce := func(tok string) (*http.Response, error) {
		r, err := c.doWithJWT(ctx, method, path, newReader(), tok, extraHeaders)
		if err != nil {
			return nil, err
		}
		if r.StatusCode == http.StatusUnauthorized {
			r.Body.Close()
			// Double-checked locking: only re-authenticate if another goroutine
			// has not already refreshed the token while we waited.
			c.mu.Lock()
			if c.jwt == tok {
				// Token is still the stale one — we must refresh. Unlock
				// before making the HTTP call to avoid holding the mutex
				// across the network round-trip.
				c.mu.Unlock()
				if authErr := c.authenticate(ctx); authErr != nil {
					return nil, authErr
				}
			} else {
				// Another goroutine already refreshed the token; just use it.
				c.mu.Unlock()
			}
			c.mu.RLock()
			tok = c.jwt
			c.mu.RUnlock()
			r, err = c.doWithJWT(ctx, method, path, newReader(), tok, extraHeaders)
			if err != nil {
				return nil, err
			}
		}
		if r.StatusCode == http.StatusTooManyRequests {
			retryAfter, _ := strconv.Atoi(r.Header.Get("Retry-After"))
			if retryAfter > 0 && retryAfter <= 60 {
				r.Body.Close()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(retryAfter) * time.Second):
				}
				r, err = c.doWithJWT(ctx, method, path, newReader(), tok, extraHeaders)
				if err != nil {
					return nil, err
				}
				return r, nil
			}
			// retryAfter > 60 or not present: return immediately.
			raw, _ := io.ReadAll(r.Body)
			r.Body.Close()
			return nil, &RateLimitError{
				Message:    fmt.Sprintf("rate limited (HTTP 429): %s", string(raw)),
				RetryAfter: retryAfter,
			}
		}
		return r, nil
	}

	resp, err := doOnce(jwt)
	if err != nil {
		return nil, err
	}

	// Retry up to 2 times on 5xx with exponential backoff.
	retryDelays := []time.Duration{1 * time.Second, 2 * time.Second}
	for _, delay := range retryDelays {
		if resp.StatusCode < 500 {
			break
		}
		resp.Body.Close()
		// Re-capture token in case a 401 refresh updated it during a previous attempt.
		c.mu.RLock()
		tok := c.jwt
		c.mu.RUnlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		resp, err = doOnce(tok)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// newRequestID generates a random hex request ID for X-Request-ID headers.
func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

func (c *APIGuardClient) doWithJWT(ctx context.Context, method, path string, body io.Reader, jwt string, extraHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Request-ID", newRequestID())
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return c.HTTPClient.Do(req)
}

// checkResponse reads the response body and returns a decoded error when the
// status code is >= 400. On success it returns the raw body for the caller to
// decode.  HTTP 429 is reported with a "rate limited" prefix so callers can
// detect and handle it distinctly.
func checkResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		ra, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return nil, &RateLimitError{
			Message:    fmt.Sprintf("rate limited (HTTP 429): %s", string(raw)),
			RetryAfter: ra,
		}
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

// deleteJSON issues a DELETE request. A 204 No Content response is treated as
// success. Any body in a 2xx response is discarded.
func (c *APIGuardClient) deleteJSON(ctx context.Context, path string) error {
	resp, err := c.do(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode >= 400 {
		var ae apiError
		if jsonErr := json.Unmarshal(raw, &ae); jsonErr == nil && (ae.Error != "" || ae.Message != "") {
			return fmt.Errorf("API error HTTP %d: %s — %s", resp.StatusCode, ae.Error, ae.Message)
		}
		return fmt.Errorf("API error HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return nil
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

// GetFindingsOptions holds optional filter and pagination parameters for GetFindings.
type GetFindingsOptions struct {
	// Page is the 1-based page number (default: 1).
	Page int
	// PerPage is the number of results per page, max 100 (default: 100).
	PerPage int
	// Status filters by finding status (e.g. "open", "confirmed").
	Status string
	// Severity filters by finding severity (e.g. "critical", "high").
	Severity string
}

// GetFindings returns findings for a completed scan with optional filtering.
// Results are fetched from GET /api/v1/scans/{id}/findings.
// Pass a zero-value GetFindingsOptions{} to use server defaults (page 1, per_page 100).
func (c *APIGuardClient) GetFindings(ctx context.Context, scanID string, opts GetFindingsOptions) ([]Finding, error) {
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 100
	}
	if perPage > 100 {
		perPage = 100
	}

	params := url.Values{}
	params.Set("page", strconv.Itoa(page))
	params.Set("per_page", strconv.Itoa(perPage))
	if opts.Status != "" {
		params.Set("status", opts.Status)
	}
	if opts.Severity != "" {
		params.Set("severity", opts.Severity)
	}

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

// GetReport fetches the scan report in the requested format and returns the raw bytes.
// format must be one of "json" (default), "sarif", "html", "pdf".
// Issues GET /api/v1/scans/{id}/report?format={format}.
//
// The request uses a dedicated timeout from ReportTimeout (default 120s) rather
// than the general HTTPClient timeout, because report generation can be slow.
func (c *APIGuardClient) GetReport(ctx context.Context, scanID, format string) ([]byte, error) {
	timeout := c.ReportTimeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if format == "" {
		format = "json"
	}
	params := url.Values{}
	params.Set("format", format)
	fullPath := fmt.Sprintf("scans/%s/report?%s", scanID, params.Encode())
	resp, err := c.do(ctx, http.MethodGet, fullPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("GetReport %s: %w", scanID, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GetReport %s: reading response: %w", scanID, err)
	}
	if resp.StatusCode >= 400 {
		var ae apiError
		if jsonErr := json.Unmarshal(data, &ae); jsonErr == nil && (ae.Error != "" || ae.Message != "") {
			return nil, fmt.Errorf("GetReport %s: API error HTTP %d: %s — %s", scanID, resp.StatusCode, ae.Error, ae.Message)
		}
		return nil, fmt.Errorf("GetReport %s: API error HTTP %d: %s", scanID, resp.StatusCode, string(data))
	}
	return data, nil
}

// UploadSpec uploads a local OpenAPI spec file to the server via multipart/form-data.
// Issues POST /api/v1/specs/upload and returns the stored path, hash, and size.
func (c *APIGuardClient) UploadSpec(ctx context.Context, filePath string) (*UploadSpecResponse, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("UploadSpec: opening file: %w", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("spec", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("UploadSpec: creating form file: %w", err)
	}
	// Write the file content into the multipart part.
	// Note: the multipart body is buffered in memory before sending.
	// For very large files consider using a streaming upload instead.
	if _, err := io.Copy(fw, f); err != nil {
		return nil, fmt.Errorf("UploadSpec: writing file content: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("UploadSpec: closing multipart writer: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPost, "specs/upload", &buf,
		map[string]string{"Content-Type": mw.FormDataContentType()})
	if err != nil {
		return nil, fmt.Errorf("UploadSpec: %w", err)
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("UploadSpec: %w", err)
	}
	var result UploadSpecResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("UploadSpec: decoding response: %w", err)
	}
	return &result, nil
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

// GetAuditLog retrieves audit log entries with pagination support.
// limit is capped at 100 client-side when it exceeds 100.
// page is the 1-based page number; defaults to 1 when <= 0.
func (c *APIGuardClient) GetAuditLog(ctx context.Context, limit, page int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if page <= 0 {
		page = 1
	}
	params := url.Values{}
	params.Set("per_page", strconv.Itoa(limit))
	params.Set("page", strconv.Itoa(page))

	var entries []AuditEntry
	if err := c.getJSON(ctx, "audit", params, &entries); err != nil {
		return nil, fmt.Errorf("GetAuditLog: %w", err)
	}
	return entries, nil
}

// ListScans returns a paginated list of scans from GET /api/v1/scans.
func (c *APIGuardClient) ListScans(ctx context.Context, opts ListScansOptions) ([]Scan, error) {
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	params := url.Values{}
	params.Set("page", strconv.Itoa(page))
	params.Set("per_page", strconv.Itoa(perPage))

	var envelope scansResponse
	if err := c.getJSON(ctx, "scans", params, &envelope); err != nil {
		return nil, fmt.Errorf("ListScans: %w", err)
	}
	return envelope.Items, nil
}

// DeleteScan deletes a scan by UUID via DELETE /api/v1/scans/{id}.
func (c *APIGuardClient) DeleteScan(ctx context.Context, scanID string) error {
	if err := c.deleteJSON(ctx, "scans/"+scanID); err != nil {
		return fmt.Errorf("DeleteScan %s: %w", scanID, err)
	}
	return nil
}

// ListFindings returns a paginated list of findings from GET /api/v1/findings.
// Optionally filter by scan UUID via opts.ScanID.
func (c *APIGuardClient) ListFindings(ctx context.Context, opts ListFindingsOptions) ([]Finding, error) {
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	params := url.Values{}
	params.Set("page", strconv.Itoa(page))
	params.Set("per_page", strconv.Itoa(perPage))
	if opts.ScanID != "" {
		params.Set("scan_id", opts.ScanID)
	}

	fullPath := "findings?" + params.Encode()
	resp, err := c.do(ctx, http.MethodGet, fullPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ListFindings: %w", err)
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("ListFindings: %w", err)
	}
	// Try envelope format {"data": [...]} first, then plain array.
	var envelope findingsResponse
	if jsonErr := json.Unmarshal(raw, &envelope); jsonErr == nil && envelope.Data != nil {
		return envelope.Data, nil
	}
	var findings []Finding
	if jsonErr := json.Unmarshal(raw, &findings); jsonErr != nil {
		return nil, fmt.Errorf("ListFindings: unexpected response format: %w", jsonErr)
	}
	return findings, nil
}

// GetFinding retrieves a single finding by UUID via GET /api/v1/findings/{id}.
func (c *APIGuardClient) GetFinding(ctx context.Context, findingID string) (*Finding, error) {
	var finding Finding
	if err := c.getJSON(ctx, "findings/"+findingID, nil, &finding); err != nil {
		return nil, fmt.Errorf("GetFinding %s: %w", findingID, err)
	}
	return &finding, nil
}

// RefreshToken exchanges a refresh token for a new access token via
// POST /api/v1/auth/refresh (no JWT required). Updates the cached token on success.
func (c *APIGuardClient) RefreshToken(ctx context.Context, refreshToken string) (*RefreshTokenResponse, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL("auth/refresh"), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("RefreshToken: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RefreshToken: request failed: %w", err)
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("RefreshToken: %w", err)
	}
	var result RefreshTokenResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("RefreshToken: decoding response: %w", err)
	}
	if result.AccessToken != "" {
		expiry, err := parseJWTExpiry(result.AccessToken)
		if err != nil {
			expiry = time.Now().Add(5 * time.Minute)
		}
		c.mu.Lock()
		c.jwt = result.AccessToken
		c.tokenExpiry = expiry
		c.mu.Unlock()
	}
	return &result, nil
}
