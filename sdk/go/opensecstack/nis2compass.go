package opensecstack

import (
	"bytes"
	"context"
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

	mu  sync.Mutex
	jwt string // cached Bearer token; empty means unauthenticated
}

// NewNIS2CompassClient creates a NIS2CompassClient with sensible defaults.
func NewNIS2CompassClient(baseURL, apiKey string) *NIS2CompassClient {
	return &NIS2CompassClient{
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

func (c *NIS2CompassClient) apiURL(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.BaseURL, strings.TrimLeft(path, "/"))
}

// authenticate exchanges the API key for a JWT and caches it.
// Must be called with c.mu held.
func (c *NIS2CompassClient) authenticate(ctx context.Context) error {
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
	c.jwt = token
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

	c.mu.Lock()
	if c.jwt == "" {
		if err := c.authenticate(ctx); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}
	jwt := c.jwt
	c.mu.Unlock()

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
			c.mu.Lock()
			if authErr := c.authenticate(ctx); authErr != nil {
				c.mu.Unlock()
				return nil, authErr
			}
			tok = c.jwt
			c.mu.Unlock()
			r, err = doReq(tok)
			if err != nil {
				return nil, err
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
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		resp, err = doOnce(c.jwt)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
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

// GetOrganisations returns the first page of organisations (up to 100 items).
// Callers that need to retrieve more than 100 organisations should use the
// pagination parameters directly via the underlying API.
func (c *NIS2CompassClient) GetOrganisations(ctx context.Context) ([]Organisation, error) {
	params := url.Values{}
	params.Set("page", "1")
	params.Set("per_page", "100")

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
// Pass a zero-value GetAssessmentsOptions{} to use server defaults
// (page 1, per_page 100, no status filter).
func (c *NIS2CompassClient) GetAssessments(ctx context.Context, orgID string, opts GetAssessmentsOptions) ([]Assessment, error) {
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	perPage := opts.PerPage
	if perPage <= 0 {
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

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("UploadArtifact: reading file: %w", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	fw, err := mw.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("UploadArtifact: creating form file: %w", err)
	}
	if _, err := fw.Write(content); err != nil {
		return nil, fmt.Errorf("UploadArtifact: writing file content: %w", err)
	}

	if err := mw.WriteField("type", artifactType); err != nil {
		return nil, fmt.Errorf("UploadArtifact: writing type field: %w", err)
	}
	if controlID != "" {
		if err := mw.WriteField("control_id", controlID); err != nil {
			return nil, fmt.Errorf("UploadArtifact: writing control_id field: %w", err)
		}
	}
	if description != "" {
		if err := mw.WriteField("description", description); err != nil {
			return nil, fmt.Errorf("UploadArtifact: writing description field: %w", err)
		}
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("UploadArtifact: closing multipart writer: %w", err)
	}

	path := "assessments/" + assessmentID + "/artifacts"
	resp, err := c.do(ctx, http.MethodPost, path, &buf,
		map[string]string{"Content-Type": mw.FormDataContentType()})
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
func (c *NIS2CompassClient) GenerateReport(ctx context.Context, assessmentID string) ([]byte, error) {
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

// GetAuditLog retrieves the most recent NIS2 audit log entries (up to limit).
// When limit is <= 0 a default of 50 is used.
func (c *NIS2CompassClient) GetAuditLog(ctx context.Context, limit int) ([]NIS2AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	params := url.Values{}
	params.Set("per_page", strconv.Itoa(limit))

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
