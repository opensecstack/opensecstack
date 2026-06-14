package governance

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

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// NIS2Client talks to NIS2 Compass. Article 23 notifications are recorded by
// updating the "Incident Handling" control on a pre-existing assessment.
//
// Authentication is bearer JWT obtained by exchanging an API key against
// /api/v1/auth/token. The client caches the token until 60 seconds before
// its expiry and refreshes transparently on subsequent calls.
type NIS2Client struct {
	baseURL      string
	apiKey       string
	assessmentID string
	measureRef   string
	http         *http.Client

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NIS2ClientConfig bundles the constructor inputs.
type NIS2ClientConfig struct {
	BaseURL      string
	APIKey       string
	AssessmentID string
	MeasureRef   string // defaults to "b" (Article 21(2)(b) — Incident Handling)
	Timeout      time.Duration
}

// NewNIS2Client constructs an NIS2Client.
func NewNIS2Client(cfg NIS2ClientConfig) *NIS2Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MeasureRef == "" {
		cfg.MeasureRef = "b"
	}
	return &NIS2Client{
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:       cfg.APIKey,
		assessmentID: cfg.AssessmentID,
		measureRef:   cfg.MeasureRef,
		http:         &http.Client{Timeout: cfg.Timeout},
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

type authTokenRequest struct {
	APIKey string `json:"api_key"`
}

type authTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type patchControlRequest struct {
	Status          string                 `json:"status,omitempty"`
	Evidence        map[string]interface{} `json:"evidence,omitempty"`
	GapDescription  string                 `json:"gap_description,omitempty"`
	RemediationPlan string                 `json:"remediation_plan,omitempty"`
	RiskScore       *float64               `json:"risk_score,omitempty"`
	Notes           string                 `json:"notes,omitempty"`
}

// NotifyIncident records the incident against the configured assessment's
// Incident Handling control. It is a no-op (with nil error) when the client
// is not fully configured, so the incident Service can invoke it
// unconditionally.
func (c *NIS2Client) NotifyIncident(ctx context.Context, inc *incident.Incident) error {
	if c.baseURL == "" || c.apiKey == "" || c.assessmentID == "" {
		return nil
	}

	riskScore := severityToRiskScore(inc.Severity)
	evidence := map[string]interface{}{
		"incident_id":    inc.ID,
		"severity":       string(inc.Severity),
		"source":         string(inc.Source),
		"source_ref":     inc.SourceRef,
		"title":          inc.Title,
		"detection_time": inc.CreatedAt.UTC().Format(time.RFC3339),
		"nis2_deadline":  nis2Deadline(inc),
		"project_id":     inc.ProjectID,
	}

	payload := patchControlRequest{
		Status:          "non_compliant",
		Evidence:        evidence,
		GapDescription:  fmt.Sprintf("Incident %s (%s): %s", inc.ID, inc.Severity, inc.Title),
		RemediationPlan: firstNonEmpty(inc.CorrectiveAction, "Incident response in progress — see IRFlow timeline"),
		RiskScore:       &riskScore,
		Notes:           fmt.Sprintf("NIS2 Article 23 notification pending — deadline %s", nis2Deadline(inc)),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling control patch: %w", err)
	}

	path := fmt.Sprintf("/api/v1/assessments/%s/controls/%s", c.assessmentID, c.measureRef)
	status, respBody, err := c.authed(ctx, http.MethodPatch, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("nis2 patch control: status %d: %s", status, string(respBody))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Token caching & HTTP plumbing
// ---------------------------------------------------------------------------

// authed issues an authenticated request and returns (status, body, err).
// The response body is fully drained and closed inside this helper.
func (c *NIS2Client) authed(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return 0, nil, err
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

func (c *NIS2Client) getToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	// Refresh 60 seconds before expiry to avoid racing with a near-expired token.
	if c.token != "" && time.Until(c.tokenExpiry) > 60*time.Second {
		return c.token, nil
	}

	body, err := json.Marshal(authTokenRequest{APIKey: c.apiKey})
	if err != nil {
		return "", fmt.Errorf("marshalling auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/auth/token", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("reading auth response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("nis2 auth: status %d: %s", resp.StatusCode, string(respBody))
	}

	var out authTokenResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("parsing auth response: %w", err)
	}
	c.token = out.Token
	c.tokenExpiry = out.ExpiresAt
	return c.token, nil
}

func severityToRiskScore(s incident.Severity) float64 {
	switch s {
	case incident.SeverityP1:
		return 9.5
	case incident.SeverityP2:
		return 7.5
	case incident.SeverityP3:
		return 5.0
	case incident.SeverityP4:
		return 2.5
	}
	return 5.0
}

func nis2Deadline(inc *incident.Incident) string {
	if d, ok := incident.NIS2Thresholds[inc.Severity]; ok && d > 0 {
		return inc.CreatedAt.Add(d).UTC().Format(time.RFC3339)
	}
	return ""
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
