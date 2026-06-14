// Package advisory bridges the Go API to the Python advisory subsystem
// (CSAF 2.0 generation, IOC enrichment, abuse-mailbox triage).
package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// BuildAdvisoryURL constructs the base URL for the Python advisory service.
//
// Priority (matches what config.go exposes to main.go):
//  1. explicit — use as-is when non-empty (OPENCSIRT_ADVISORY_SERVICE_URL).
//  2. host + port — mirrors the Python service's own OPENCSIRT_PY_HOST /
//     OPENCSIRT_PY_PORT env vars so both sides agree on the address without
//     requiring the operator to duplicate the value.
//  3. Default to http://localhost:8089 (Python service default).
func BuildAdvisoryURL(explicit, host, port string) string {
	if explicit != "" {
		return explicit
	}
	h := host
	if h == "" {
		h = "localhost"
	}
	p := port
	if p == "" {
		p = "8089"
	}
	return "http://" + h + ":" + p
}

// PythonClient is the abstraction the service depends on.
// `httpClient` calls the real FastAPI service; `noopClient` returns a
// deterministic stub used in dev / tests when the Python service is
// not running.
type PythonClient interface {
	Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error)
	// Deprecated: never called by any production code path; pending removal in v1.1.
	// TODO(v1.1): remove after confirming no external callers depend on this interface method.
	EnrichIOCs(ctx context.Context, iocs []IOC) ([]EnrichedIOC, error)
	// Deprecated: never called by any production code path; pending removal in v1.1.
	// TODO(v1.1): remove after confirming no external callers depend on this interface method.
	TriageAbuseEmail(ctx context.Context, raw []byte) (TriageResult, error)
	Health(ctx context.Context) error
}

type GenerateRequest struct {
	IncidentID    string                 `json:"incident_id,omitempty"`
	Title         string                 `json:"title"`
	Summary       string                 `json:"summary"`
	TLP           string                 `json:"tlp"`
	IOCs          []IOC                  `json:"iocs,omitempty"`
	Vulnerability map[string]any         `json:"vulnerability,omitempty"`
	Extras        map[string]any         `json:"extras,omitempty"`
}

type GenerateResponse struct {
	CSAFID  string                 `json:"csaf_id"`
	Doc     map[string]any         `json:"csaf_doc"`
}

type IOC struct {
	Type  string `json:"type"`  // ip|domain|url|hash
	Value string `json:"value"`
}

type EnrichedIOC struct {
	IOC
	Reputation int                    `json:"reputation"` // 0-100
	Tags       []string               `json:"tags"`
	Sources    []string               `json:"sources"`
	Extra      map[string]any         `json:"extra,omitempty"`
}

type TriageResult struct {
	Classification string   `json:"classification"` // phishing|malware|scam|legitimate|unknown
	Confidence     float64  `json:"confidence"`
	IOCsExtracted  []IOC    `json:"iocs_extracted"`
	YARAMatches    []string `json:"yara_matches"`
}

// ErrAdvisoryUpstream is the generic sentinel returned to API callers when the
// Python service responds with a non-2xx status. The raw body is never forwarded.
var ErrAdvisoryUpstream = errors.New("advisory service error")

type httpClient struct {
	baseURL string
	jwt     string
	http    *http.Client
	log     zerolog.Logger
}

func NewHTTPClient(baseURL, jwt string) PythonClient {
	return &httpClient{
		baseURL: baseURL,
		jwt:     jwt,
		http:    &http.Client{Timeout: 30 * time.Second},
		log:     zerolog.Nop(),
	}
}

func (c *httpClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	var resp GenerateResponse
	err := c.post(ctx, "/generate", req, &resp)
	return resp, err
}

func (c *httpClient) EnrichIOCs(ctx context.Context, iocs []IOC) ([]EnrichedIOC, error) {
	var resp struct {
		IOCs []EnrichedIOC `json:"iocs"`
	}
	err := c.post(ctx, "/enrich/iocs", map[string]any{"iocs": iocs}, &resp)
	return resp.IOCs, err
}

func (c *httpClient) TriageAbuseEmail(ctx context.Context, raw []byte) (TriageResult, error) {
	var resp TriageResult
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/triage/abuse-email", bytes.NewReader(raw))
	if err != nil {
		return resp, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	c.authHeader(req)
	httpResp, err := c.http.Do(req)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 400 {
		// Log raw body at error level for operator visibility; never forward it to callers.
		rawBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		c.log.Error().Int("status", httpResp.StatusCode).Bytes("body", rawBody).
			Msg("advisory python: triage upstream error")
		return resp, fmt.Errorf("%w: status %d", ErrAdvisoryUpstream, httpResp.StatusCode)
	}
	return resp, json.NewDecoder(httpResp.Body).Decode(&resp)
}

func (c *httpClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	c.authHeader(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("advisory python: health %d", resp.StatusCode)
	}
	return nil
}

func (c *httpClient) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.authHeader(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Log raw body for operator visibility; never forward it to callers.
		rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		c.log.Error().Int("status", resp.StatusCode).Bytes("body", rawBody).
			Str("path", path).Msg("advisory python: upstream error")
		return fmt.Errorf("%w: status %d", ErrAdvisoryUpstream, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *httpClient) authHeader(req *http.Request) {
	if c.jwt != "" {
		req.Header.Set("Authorization", "Bearer "+c.jwt)
	}
}

// NoopClient generates a deterministic stub CSAF 2.0 document. Used
// when the Python service is not configured (dev mode, smoke tests).
type NoopClient struct{}

func (NoopClient) Generate(_ context.Context, req GenerateRequest) (GenerateResponse, error) {
	csafID := "CSAF-OCS-STUB-" + req.Title
	if csafID == "CSAF-OCS-STUB-" {
		return GenerateResponse{}, errors.New("noop: title required")
	}
	doc := map[string]any{
		"document": map[string]any{
			"category":     "csaf_security_advisory",
			"csaf_version": "2.0",
			"title":        req.Title,
			"publisher": map[string]any{
				"category": "coordinator",
				"name":     "OpenCSIRT (stub)",
			},
			"tracking": map[string]any{
				"id":              csafID,
				"current_release": "1",
				"initial_release_date": time.Now().UTC().Format(time.RFC3339),
				"status":          "draft",
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": req.TLP},
			},
		},
	}
	return GenerateResponse{CSAFID: csafID, Doc: doc}, nil
}

func (NoopClient) EnrichIOCs(_ context.Context, iocs []IOC) ([]EnrichedIOC, error) {
	out := make([]EnrichedIOC, 0, len(iocs))
	for _, i := range iocs {
		out = append(out, EnrichedIOC{IOC: i, Reputation: 0, Tags: []string{"unenriched"}, Sources: nil})
	}
	return out, nil
}

func (NoopClient) TriageAbuseEmail(_ context.Context, _ []byte) (TriageResult, error) {
	return TriageResult{Classification: "unknown", Confidence: 0}, nil
}

func (NoopClient) Health(_ context.Context) error { return nil }
