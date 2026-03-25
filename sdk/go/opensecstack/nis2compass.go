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
	"time"
)

// NIS2CompassClient is an HTTP client for the NIS2 Compass API.
//
// Authentication uses a direct API key sent as the X-API-Key request header.
// No token exchange is required; the key is included on every request.
type NIS2CompassClient struct {
	// BaseURL is the root URL of the NIS2 Compass instance (no trailing slash).
	BaseURL string
	// APIKey is the pre-shared key included on every request via X-API-Key.
	APIKey string
	// HTTPClient is the underlying HTTP client. A default client with a
	// 30-second timeout is used when nil.
	HTTPClient *http.Client
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

// do builds and executes an authenticated HTTP request.
func (c *NIS2CompassClient) do(ctx context.Context, method, path string, body io.Reader, extraHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return c.HTTPClient.Do(req)
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

// ----------------------------------------------------------------------------
// Organisations
// ----------------------------------------------------------------------------

// GetOrganisations returns all organisations. All pages are fetched automatically
// and the full list is returned to the caller.
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

// ----------------------------------------------------------------------------
// Assessments
// ----------------------------------------------------------------------------

// GetAssessments returns all assessments belonging to the given organisation UUID.
func (c *NIS2CompassClient) GetAssessments(ctx context.Context, orgID string) ([]Assessment, error) {
	params := url.Values{}
	params.Set("page", "1")
	params.Set("per_page", "100")

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
