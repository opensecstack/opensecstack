package opensecstack

import (
	"bytes"
	"context"
	"encoding/base64"
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

// NIS2CompassClient is an HTTP client for the NIS2 Compass API.
//
// Authentication uses a two-step flow: the APIKey is exchanged for a
// short-lived JWT via POST /api/v1/auth/token. The JWT is cached and
// refreshed automatically on expiry (HTTP 401).
type NIS2CompassClient struct {
	// BaseURL is the root URL of the NIS2 Compass instance (no trailing slash).
	BaseURL string
	// APIKey is the pre-shared key used to obtain JWTs.
	APIKey string
	// HTTPClient is the underlying HTTP client. A default client with a
	// 30-second timeout is used when nil.
	HTTPClient *http.Client
	// ReportTimeout is the maximum time to wait for GenerateReport to complete.
	// When zero, it defaults to 120 seconds (matching the Python SDK).
	ReportTimeout time.Duration
	// MaxRetries is the maximum number of retry attempts for transient 5xx errors.
	// Zero (default) means no retries.
	MaxRetries int
	// RetryWaitBase is the base duration for exponential backoff between retries.
	// Defaults to 500ms when MaxRetries > 0.
	RetryWaitBase time.Duration

	mu          sync.RWMutex
	jwt         string    // cached Bearer token; empty means unauthenticated
	tokenExpiry time.Time // expiry time parsed from JWT exp claim
}

// NewNIS2CompassClient creates a NIS2CompassClient with sensible defaults.
func NewNIS2CompassClient(baseURL, apiKey string) *NIS2CompassClient {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // do not follow redirects
	}
	return &NIS2CompassClient{
		BaseURL:       strings.TrimRight(baseURL, "/"),
		APIKey:        apiKey,
		HTTPClient:    httpClient,
		ReportTimeout: 120 * time.Second,
	}
}

// parseJWTExpiry decodes the payload segment of a JWT and extracts the exp
// (expiry) claim, returning it as a time.Time. Returns an error if the token
// is malformed or lacks an exp claim.
func parseJWTExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("malformed JWT: expected 3 segments, got %d", len(parts))
	}
	// Add padding so base64 decoding succeeds regardless of trailing '='.
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try without padding.
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return time.Time{}, fmt.Errorf("decoding JWT payload: %w", err)
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return time.Time{}, fmt.Errorf("unmarshalling JWT claims: %w", err)
	}
	expVal, ok := claims["exp"]
	if !ok {
		return time.Time{}, fmt.Errorf("JWT has no exp claim")
	}
	// JSON numbers decode as float64.
	expFloat, ok := expVal.(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("JWT exp claim is not a number")
	}
	return time.Unix(int64(expFloat), 0), nil
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

func (c *NIS2CompassClient) apiURL(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.BaseURL, strings.TrimLeft(path, "/"))
}

// authenticate exchanges the API key for a JWT and caches it.
// It manages its own locking and must NOT be called with c.mu held.
// It uses double-checked locking so that concurrent callers only issue
// one HTTP request: if the token is already populated when the lock is
// re-acquired after the HTTP round-trip, the fresh token is discarded.
func (c *NIS2CompassClient) authenticate(ctx context.Context) error {
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
	token, _ := data["token"].(string)
	if token == "" {
		token, _ = data["access_token"].(string)
	}
	if token == "" {
		return fmt.Errorf("no token in auth response")
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

// do builds and executes an authenticated HTTP request, re-authenticating
// once on HTTP 401.
//
// The body is buffered into memory so that it can be replayed intact if the
// first attempt returns 401 and a token refresh is required.
func (c *NIS2CompassClient) do(ctx context.Context, method, path string, body io.Reader, extraHeaders map[string]string) (*http.Response, error) {
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

	doReq := func(tok string) (*http.Response, error) {
		var r io.Reader
		if bodyBuf != nil {
			r = bytes.NewReader(bodyBuf)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), r)
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Request-ID", newRequestID())
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		return c.HTTPClient.Do(req)
	}

	doOnce := func(tok string) (*http.Response, error) {
		r, err := doReq(tok)
		if err != nil {
			return nil, err
		}
		if r.StatusCode == http.StatusUnauthorized {
			r.Body.Close()
			// Double-checked locking: only re-authenticate if another thread
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
				// Another thread already refreshed the token; just use it.
				c.mu.Unlock()
			}
			c.mu.RLock()
			tok = c.jwt
			c.mu.RUnlock()
			r, err = doReq(tok)
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
				r, err = doReq(tok)
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

// doWithRetry executes an HTTP request function with exponential-backoff
// retry on transient errors (5xx responses, network timeouts).
// It does NOT retry 4xx client errors.
//
// fn must be idempotent — it is called up to MaxRetries+1 times.
// fn receives the current attempt index (0-based) and returns an *http.Response
// and error. On each retry, fn is called again with a fresh request.
func (c *NIS2CompassClient) doWithRetry(ctx context.Context, fn func(attempt int) (*http.Response, error)) (*http.Response, error) {
	maxAttempts := c.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	base := c.RetryWaitBase
	if base == 0 {
		base = 500 * time.Millisecond
	}

	var lastErr error
	var lastResp *http.Response
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := base * time.Duration(1<<(attempt-1)) // 500ms, 1s, 2s, …
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		resp, err := fn(attempt)
		if err != nil {
			lastErr = err
			lastResp = nil
			continue
		}

		// Do not retry client errors (4xx) or success (1xx/2xx/3xx).
		if resp.StatusCode < 500 {
			return resp, nil
		}

		// 5xx — consume and close body before retry.
		_ = resp.Body.Close()
		lastResp = resp
		lastErr = fmt.Errorf("server error: HTTP %d", resp.StatusCode)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return lastResp, nil
}

// GetReportStream downloads an assessment report and streams it to w.
// format must be one of "pdf", "json", "sarif".
func (c *NIS2CompassClient) GetReportStream(ctx context.Context, assessmentID, format string, w io.Writer) error {
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("GetReportStream: authenticate: %w", err)
	}

	u := c.apiURL(fmt.Sprintf("assessments/%s/report?format=%s", assessmentID, format))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return fmt.Errorf("GetReportStream: build request: %w", err)
	}
	c.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+c.jwt)
	c.mu.RUnlock()

	resp, err := c.doWithRetry(ctx, func(_ int) (*http.Response, error) {
		r := req.Clone(ctx)
		return c.HTTPClient.Do(r)
	})
	if err != nil {
		return fmt.Errorf("GetReportStream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GetReportStream: HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (c *NIS2CompassClient) getJSON(ctx context.Context, path string, params url.Values, out interface{}) error {
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

func (c *NIS2CompassClient) postJSON(ctx context.Context, path string, reqBody interface{}, out interface{}) error {
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
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *NIS2CompassClient) patchJSON(ctx context.Context, path string, reqBody interface{}, out interface{}) error {
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

func (c *NIS2CompassClient) deleteJSON(ctx context.Context, path string) error {
	resp, err := c.do(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return err
	}
	_, err = checkResponse(resp)
	return err
}

// ----------------------------------------------------------------------------
// Organisations
// ----------------------------------------------------------------------------

// GetOrganisations returns a paginated list of organisations.
//
// opts controls pagination. Pass a zero-value GetOrganisationsOptions{} to
// use defaults (page 1, per_page 20). PerPage is clamped to 100 when greater.
func (c *NIS2CompassClient) GetOrganisations(ctx context.Context, opts GetOrganisationsOptions) ([]Organisation, error) {
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

	var orgs []Organisation
	if err := c.getJSON(ctx, "organisations", params, &orgs); err != nil {
		return nil, fmt.Errorf("GetOrganisations: %w", err)
	}
	return orgs, nil
}

// CreateOrganisation registers a new organisation.
func (c *NIS2CompassClient) CreateOrganisation(ctx context.Context, req CreateOrganisationRequest) (*Organisation, error) {
	var org Organisation
	if err := c.postJSON(ctx, "organisations", req, &org); err != nil {
		return nil, fmt.Errorf("CreateOrganisation: %w", err)
	}
	return &org, nil
}

// GetOrganisation retrieves a single organisation by its UUID.
func (c *NIS2CompassClient) GetOrganisation(ctx context.Context, id string) (*Organisation, error) {
	var org Organisation
	if err := c.getJSON(ctx, "organisations/"+id, nil, &org); err != nil {
		return nil, fmt.Errorf("GetOrganisation %s: %w", id, err)
	}
	return &org, nil
}

// PatchOrganisation updates one or more fields on an organisation.
// Only fields present in req are modified; omitted fields retain their current values.
func (c *NIS2CompassClient) PatchOrganisation(ctx context.Context, id string, req PatchOrganisationRequest) (*Organisation, error) {
	var org Organisation
	if err := c.patchJSON(ctx, "organisations/"+id, req, &org); err != nil {
		return nil, fmt.Errorf("PatchOrganisation %s: %w", id, err)
	}
	return &org, nil
}

// DeleteOrganisation permanently removes an organisation and all its assessments.
// The server returns HTTP 204 on success.
func (c *NIS2CompassClient) DeleteOrganisation(ctx context.Context, id string) error {
	if err := c.deleteJSON(ctx, "organisations/"+id); err != nil {
		return fmt.Errorf("DeleteOrganisation %s: %w", id, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Assessments
// ----------------------------------------------------------------------------

// GetAssessments returns assessments belonging to the given organisation UUID.
//
// opts controls pagination and optional server-side filtering by status.
// Pass a zero-value GetAssessmentsOptions{} to use defaults
// (page 1, per_page 20, no status filter). PerPage is clamped to 100 when greater.
func (c *NIS2CompassClient) GetAssessments(ctx context.Context, orgID string, opts GetAssessmentsOptions) ([]Assessment, error) {
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
	if opts.Status != "" {
		params.Set("status", opts.Status)
	}

	var assessments []Assessment
	if err := c.getJSON(ctx, "organisations/"+orgID+"/assessments", params, &assessments); err != nil {
		return nil, fmt.Errorf("GetAssessments org=%s: %w", orgID, err)
	}
	return assessments, nil
}

// CreateAssessment creates a new assessment for an organisation.
// The server automatically seeds 10 control entries (NIS2 Article 21(2) measures a–j).
func (c *NIS2CompassClient) CreateAssessment(ctx context.Context, orgID string, req CreateAssessmentRequest) (*Assessment, error) {
	var assessment Assessment
	if err := c.postJSON(ctx, "organisations/"+orgID+"/assessments", req, &assessment); err != nil {
		return nil, fmt.Errorf("CreateAssessment org=%s: %w", orgID, err)
	}
	return &assessment, nil
}

// GetAssessment retrieves a single assessment by its UUID. The response includes
// a summary block with aggregated control status counts and the overall risk score.
func (c *NIS2CompassClient) GetAssessment(ctx context.Context, id string) (*Assessment, error) {
	var assessment Assessment
	if err := c.getJSON(ctx, "assessments/"+id, nil, &assessment); err != nil {
		return nil, fmt.Errorf("GetAssessment %s: %w", id, err)
	}
	return &assessment, nil
}

// PatchAssessment updates one or more fields on an assessment.
// Only fields present in req are modified; omitted fields retain their current values.
// Status transitions must follow the NIS2 Compass state machine.
func (c *NIS2CompassClient) PatchAssessment(ctx context.Context, id string, req PatchAssessmentRequest) (*Assessment, error) {
	var assessment Assessment
	if err := c.patchJSON(ctx, "assessments/"+id, req, &assessment); err != nil {
		return nil, fmt.Errorf("PatchAssessment %s: %w", id, err)
	}
	return &assessment, nil
}

// DeleteAssessment permanently removes an assessment and its associated controls.
// The server returns HTTP 204 on success.
func (c *NIS2CompassClient) DeleteAssessment(ctx context.Context, id string) error {
	if err := c.deleteJSON(ctx, "assessments/"+id); err != nil {
		return fmt.Errorf("DeleteAssessment %s: %w", id, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Controls
// ----------------------------------------------------------------------------

// GetControls returns all 10 control entries for the given assessment UUID.
func (c *NIS2CompassClient) GetControls(ctx context.Context, assessmentID string) ([]Control, error) {
	var controls []Control
	if err := c.getJSON(ctx, "assessments/"+assessmentID+"/controls", nil, &controls); err != nil {
		return nil, fmt.Errorf("GetControls assessment=%s: %w", assessmentID, err)
	}
	return controls, nil
}

// ListControlsOptions holds optional filter parameters for ListControls.
type ListControlsOptions struct {
	// Status filters by control status (e.g. "compliant", "non_compliant").
	Status string
	// NistCategory filters by NIST CSF category (e.g. "identify", "protect").
	NistCategory string
	// MeasureRef filters by a single measure reference letter ('a' through 'j').
	MeasureRef string
}

// ListControls returns control entries for the given assessment UUID, with
// optional server-side filtering. Pass a zero-value ListControlsOptions{} to
// return all controls (equivalent to GetControls).
func (c *NIS2CompassClient) ListControls(ctx context.Context, assessmentID string, opts ListControlsOptions) ([]Control, error) {
	params := url.Values{}
	if opts.Status != "" {
		params.Set("status", opts.Status)
	}
	if opts.NistCategory != "" {
		params.Set("nist_category", opts.NistCategory)
	}
	if opts.MeasureRef != "" {
		params.Set("measure_ref", opts.MeasureRef)
	}

	var controls []Control
	if err := c.getJSON(ctx, "assessments/"+assessmentID+"/controls", params, &controls); err != nil {
		return nil, fmt.Errorf("ListControls assessment=%s: %w", assessmentID, err)
	}
	return controls, nil
}

// GetControl retrieves a single NIS2 control by its measure reference letter ('a'–'j').
func (c *NIS2CompassClient) GetControl(ctx context.Context, assessmentID, measureRef string) (*Control, error) {
	path := fmt.Sprintf("assessments/%s/controls/%s", assessmentID, measureRef)
	var control Control
	if err := c.getJSON(ctx, path, nil, &control); err != nil {
		return nil, fmt.Errorf("GetControl assessment=%s measure=%s: %w", assessmentID, measureRef, err)
	}
	return &control, nil
}

// PatchControl updates the assessment findings for a single NIS2 control.
// measureRef is the single-character measure reference ('a' through 'j').
// Only fields present in req are modified.
func (c *NIS2CompassClient) PatchControl(ctx context.Context, assessmentID, measureRef string, req PatchControlRequest) (*Control, error) {
	path := fmt.Sprintf("assessments/%s/controls/%s", assessmentID, measureRef)
	var control Control
	if err := c.patchJSON(ctx, path, req, &control); err != nil {
		return nil, fmt.Errorf("PatchControl assessment=%s measure=%s: %w", assessmentID, measureRef, err)
	}
	return &control, nil
}

// ----------------------------------------------------------------------------
// Artifacts
// ----------------------------------------------------------------------------

// ListArtifacts returns all artifacts attached to the given assessment UUID.
func (c *NIS2CompassClient) ListArtifacts(ctx context.Context, assessmentID string) ([]Artifact, error) {
	var artifacts []Artifact
	if err := c.getJSON(ctx, "assessments/"+assessmentID+"/artifacts", nil, &artifacts); err != nil {
		return nil, fmt.Errorf("ListArtifacts assessment=%s: %w", assessmentID, err)
	}
	return artifacts, nil
}

// UploadArtifact uploads a local file as an artifact linked to an assessment.
// artifactType must be one of: policy, procedure, evidence, report,
// screenshot, log, certificate, contract.
// controlID and description are optional (pass "" to omit).
func (c *NIS2CompassClient) UploadArtifact(ctx context.Context, assessmentID, filePath, artifactType, controlID, description string) (*Artifact, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("UploadArtifact: opening file: %w", err)
	}
	defer f.Close()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	go func() {
		fw, err := mw.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			pw.CloseWithError(fmt.Errorf("UploadArtifact: creating form file: %w", err))
			return
		}
		if _, err := io.Copy(fw, f); err != nil {
			pw.CloseWithError(fmt.Errorf("UploadArtifact: writing file content: %w", err))
			return
		}
		if err := mw.WriteField("type", artifactType); err != nil {
			pw.CloseWithError(fmt.Errorf("UploadArtifact: writing type field: %w", err))
			return
		}
		if controlID != "" {
			if err := mw.WriteField("control_id", controlID); err != nil {
				pw.CloseWithError(fmt.Errorf("UploadArtifact: writing control_id field: %w", err))
				return
			}
		}
		if description != "" {
			if err := mw.WriteField("description", description); err != nil {
				pw.CloseWithError(fmt.Errorf("UploadArtifact: writing description field: %w", err))
				return
			}
		}
		if err := mw.Close(); err != nil {
			pw.CloseWithError(fmt.Errorf("UploadArtifact: closing multipart writer: %w", err))
			return
		}
		pw.Close()
	}()

	path := "assessments/" + assessmentID + "/artifacts"
	resp, err := c.do(ctx, http.MethodPost, path, pr,
		map[string]string{"Content-Type": contentType})
	if err != nil {
		return nil, fmt.Errorf("UploadArtifact assessment=%s: %w", assessmentID, err)
	}
	raw, err := checkResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("UploadArtifact assessment=%s: %w", assessmentID, err)
	}
	var artifact Artifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, fmt.Errorf("UploadArtifact assessment=%s: decoding response: %w", assessmentID, err)
	}
	return &artifact, nil
}

// GetArtifact retrieves artifact metadata by UUID.
func (c *NIS2CompassClient) GetArtifact(ctx context.Context, artifactID string) (*Artifact, error) {
	var artifact Artifact
	if err := c.getJSON(ctx, "artifacts/"+artifactID, nil, &artifact); err != nil {
		return nil, fmt.Errorf("GetArtifact %s: %w", artifactID, err)
	}
	return &artifact, nil
}

// DownloadArtifact downloads the file content of an artifact and writes it to destPath.
func (c *NIS2CompassClient) DownloadArtifact(ctx context.Context, artifactID, destPath string) error {
	resp, err := c.do(ctx, http.MethodGet, "artifacts/"+artifactID+"/download", nil, nil)
	if err != nil {
		return fmt.Errorf("DownloadArtifact %s: %w", artifactID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DownloadArtifact %s: API error HTTP %d: %s", artifactID, resp.StatusCode, string(raw))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("DownloadArtifact %s: reading response: %w", artifactID, err)
	}
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return fmt.Errorf("DownloadArtifact %s: writing file: %w", artifactID, err)
	}
	return nil
}

// DeleteArtifact permanently deletes an artifact and its stored file.
func (c *NIS2CompassClient) DeleteArtifact(ctx context.Context, artifactID string) error {
	if err := c.deleteJSON(ctx, "artifacts/"+artifactID); err != nil {
		return fmt.Errorf("DeleteArtifact %s: %w", artifactID, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// API key management
// ----------------------------------------------------------------------------

// ListAPIKeys returns all API keys belonging to the current actor.
func (c *NIS2CompassClient) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var keys []APIKey
	if err := c.getJSON(ctx, "api-keys", nil, &keys); err != nil {
		return nil, fmt.Errorf("ListAPIKeys: %w", err)
	}
	return keys, nil
}

// CreateAPIKey creates a new API key. The plaintext key is returned once in
// the response Key field; it is never stored server-side.
// Pass a zero-value CreateAPIKeyRequest{} to use server defaults.
func (c *NIS2CompassClient) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (*APIKey, error) {
	var key APIKey
	if err := c.postJSON(ctx, "api-keys", req, &key); err != nil {
		return nil, fmt.Errorf("CreateAPIKey: %w", err)
	}
	return &key, nil
}

// RevokeAPIKey deactivates an API key. The server returns HTTP 204 on success.
func (c *NIS2CompassClient) RevokeAPIKey(ctx context.Context, keyID string) error {
	if err := c.deleteJSON(ctx, "api-keys/"+keyID); err != nil {
		return fmt.Errorf("RevokeAPIKey %s: %w", keyID, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Reports
// ----------------------------------------------------------------------------

// GenerateReport requests a PDF compliance report for the given assessment and
// returns the raw PDF bytes. The caller is responsible for writing the bytes to
// a file or forwarding them to an HTTP response.
//
// The request uses a dedicated timeout from ReportTimeout (default 120s) rather
// than the general HTTPClient timeout, because report generation can be slow.
func (c *NIS2CompassClient) GenerateReport(ctx context.Context, assessmentID string) ([]byte, error) {
	timeout := c.ReportTimeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := c.do(ctx, http.MethodPost, "assessments/"+assessmentID+"/report", nil,
		map[string]string{"Accept": "application/pdf"})
	if err != nil {
		return nil, fmt.Errorf("GenerateReport %s: %w", assessmentID, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GenerateReport %s: reading response: %w", assessmentID, err)
	}
	if resp.StatusCode >= 400 {
		var ae apiError
		if jsonErr := json.Unmarshal(raw, &ae); jsonErr == nil && (ae.Error != "" || ae.Message != "") {
			return nil, fmt.Errorf("GenerateReport %s: API error HTTP %d: %s — %s", assessmentID, resp.StatusCode, ae.Error, ae.Message)
		}
		return nil, fmt.Errorf("GenerateReport %s: API error HTTP %d: %s", assessmentID, resp.StatusCode, string(raw))
	}
	return raw, nil
}

// ----------------------------------------------------------------------------
// Audit log
// ----------------------------------------------------------------------------

// GetAuditLog retrieves NIS2 audit log entries with pagination support.
// When limit is <= 0 a default of 50 is used.
// When page is < 1 a default of 1 is used.
func (c *NIS2CompassClient) GetAuditLog(ctx context.Context, limit int, page int) ([]NIS2AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if page < 1 {
		page = 1
	}
	params := url.Values{}
	params.Set("per_page", strconv.Itoa(limit))
	params.Set("page", strconv.Itoa(page))

	var entries []NIS2AuditEntry
	if err := c.getJSON(ctx, "audit", params, &entries); err != nil {
		return nil, fmt.Errorf("GetAuditLog: %w", err)
	}
	return entries, nil
}

// GetAuditEntry retrieves a single NIS2 audit log entry by its UUID.
func (c *NIS2CompassClient) GetAuditEntry(ctx context.Context, entryID string) (*NIS2AuditEntry, error) {
	var entry NIS2AuditEntry
	if err := c.getJSON(ctx, "audit/"+entryID, nil, &entry); err != nil {
		return nil, fmt.Errorf("GetAuditEntry %s: %w", entryID, err)
	}
	return &entry, nil
}
