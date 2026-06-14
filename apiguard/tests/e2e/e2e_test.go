//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// httpClient is a shared client with a sensible timeout for E2E tests.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// baseURL returns the APIGuard base URL from the environment or defaults to
// localhost. Set APIGUARD_TEST_URL to target a remote deployment.
func baseURL() string {
	if u := os.Getenv("APIGUARD_TEST_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

// get is a convenience wrapper that performs a GET request and returns the
// response. The caller is responsible for closing resp.Body.
func get(t *testing.T, path string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s%s", baseURL(), path)
	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// readBody drains and closes the response body, returning the raw bytes.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return body
}

// assertStatus fails the test if the response status does not match want.
func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Errorf("status: got %d, want %d", resp.StatusCode, want)
	}
}

// assertContentType fails the test if the Content-Type header does not contain
// the expected value.
func assertContentType(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		t.Errorf("Content-Type header is missing, want %q", want)
		return
	}
	// Allow e.g. "application/json; charset=utf-8"
	if len(ct) < len(want) || ct[:len(want)] != want {
		t.Errorf("Content-Type: got %q, want prefix %q", ct, want)
	}
}

// TestHealthEndpoint verifies the /api/v1/health endpoint returns 200 with a
// valid JSON body containing a "status" field set to "ok".
func TestHealthEndpoint(t *testing.T) {
	resp := get(t, "/api/v1/health")
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, body)
	}

	status, ok := payload["status"].(string)
	if !ok {
		t.Fatalf("response JSON missing \"status\" string field; got: %s", body)
	}
	if status != "ok" {
		t.Errorf("health status: got %q, want \"ok\"", status)
	}

	if _, ok := payload["timestamp"]; !ok {
		t.Errorf("health response missing \"timestamp\" field")
	}
	if _, ok := payload["uptime"]; !ok {
		t.Errorf("health response missing \"uptime\" field")
	}
}

// TestVersionEndpoint verifies the /api/v1/version endpoint returns 200 with a
// valid JSON body containing expected version metadata fields.
func TestVersionEndpoint(t *testing.T) {
	resp := get(t, "/api/v1/version")
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, body)
	}

	requiredFields := []string{"version", "git_commit", "build_date", "go_version", "os", "arch"}
	for _, field := range requiredFields {
		if _, ok := payload[field]; !ok {
			t.Errorf("version response missing %q field", field)
		}
	}
}

// TestOpenAPISpec verifies the /api/v1/openapi.json endpoint returns 200 with
// a valid JSON body that looks like an OpenAPI specification.
func TestOpenAPISpec(t *testing.T) {
	resp := get(t, "/api/v1/openapi.json")
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v\nbody: %s", err, body)
	}

	// A valid OpenAPI 3.x document must have an "openapi" version field and an
	// "info" object. A Swagger 2.x document has "swagger" instead.
	hasOpenAPI := false
	if _, ok := payload["openapi"]; ok {
		hasOpenAPI = true
	}
	if _, ok := payload["swagger"]; ok {
		hasOpenAPI = true
	}
	if !hasOpenAPI {
		t.Errorf("openapi.json does not contain an \"openapi\" or \"swagger\" field; got keys: %v", keys(payload))
	}

	if _, ok := payload["info"]; !ok {
		t.Errorf("openapi.json missing \"info\" field")
	}
}

// TestUnauthenticatedRequestsAreRejected verifies that protected endpoints
// reject requests without a Bearer token with HTTP 401.
func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	protectedPaths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/scans"},
		{http.MethodGet, "/api/v1/findings"},
		{http.MethodGet, "/api/v1/audit"},
		{http.MethodGet, "/api/v1/api-keys/"},
	}

	for _, tc := range protectedPaths {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.path), func(t *testing.T) {
			url := fmt.Sprintf("%s%s", baseURL(), tc.path)
			req, err := http.NewRequest(tc.method, url, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			// Deliberately omit Authorization header.
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", tc.method, url, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s without auth: got %d, want %d",
					tc.method, tc.path, resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

// TestFullScanWorkflow exercises the complete scan lifecycle against a live
// APIGuard instance. It requires two environment variables:
//
//	APIGUARD_E2E_URL     — base URL of the APIGuard instance (e.g. http://localhost:8080)
//	APIGUARD_E2E_API_KEY — a valid pre-shared API key configured on the instance
//
// Run:
//
//	APIGUARD_E2E_URL=http://... APIGUARD_E2E_API_KEY=... go test -tags e2e -run TestFullScanWorkflow ./tests/e2e/...
func TestFullScanWorkflow(t *testing.T) {
	e2eURL := os.Getenv("APIGUARD_E2E_URL")
	apiKey := os.Getenv("APIGUARD_E2E_API_KEY")
	if e2eURL == "" || apiKey == "" {
		t.Skip("skipping: set APIGUARD_E2E_URL and APIGUARD_E2E_API_KEY to run full scan E2E")
	}

	// ── Step 1: Authenticate ─────────────────────────────────────────────
	t.Log("Step 1: exchanging API key for JWT")
	authBody := fmt.Sprintf(`{"api_key":%q}`, apiKey)
	authResp, err := httpClient.Post(
		e2eURL+"/api/v1/auth/token",
		"application/json",
		strings.NewReader(authBody),
	)
	if err != nil {
		t.Fatalf("auth request failed: %v", err)
	}
	authRaw := readBody(t, authResp)
	assertStatus(t, authResp, http.StatusOK)

	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresIn int64  `json:"expires_in"`
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(authRaw, &tokenResp); err != nil {
		t.Fatalf("auth response is not valid JSON: %v\nbody: %s", err, authRaw)
	}
	if tokenResp.Token == "" {
		t.Fatal("auth response has empty token")
	}
	bearer := "Bearer " + tokenResp.Token

	// authedReq is a helper that creates an HTTP request with the Bearer token.
	authedReq := func(method, path string, body io.Reader) *http.Request {
		t.Helper()
		req, err := http.NewRequest(method, e2eURL+path, body)
		if err != nil {
			t.Fatalf("building %s %s request: %v", method, path, err)
		}
		req.Header.Set("Authorization", bearer)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req
	}

	// ── Step 2: Create scan ──────────────────────────────────────────────
	t.Log("Step 2: creating scan")
	// Use the health endpoint of the same instance as the scan target — it is
	// always reachable and returns a valid JSON response.
	scanTarget := e2eURL
	scanPayload := fmt.Sprintf(`{"spec_url":%q,"target":%q}`,
		e2eURL+"/api/v1/openapi.json", scanTarget)

	createResp, err := httpClient.Do(authedReq(http.MethodPost, "/api/v1/scans", strings.NewReader(scanPayload)))
	if err != nil {
		t.Fatalf("create scan request failed: %v", err)
	}
	createRaw := readBody(t, createResp)
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		t.Fatalf("create scan: got HTTP %d, want 200 or 201\nbody: %s", createResp.StatusCode, createRaw)
	}

	var scan struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(createRaw, &scan); err != nil {
		t.Fatalf("create scan response is not valid JSON: %v\nbody: %s", err, createRaw)
	}
	if scan.ID == "" {
		t.Fatalf("create scan response has empty ID; body: %s", createRaw)
	}
	scanID := scan.ID
	t.Logf("  scan created: id=%s status=%s", scanID, scan.Status)

	// ── Step 3: Poll until completed or timeout ──────────────────────────
	t.Log("Step 3: polling scan status")
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("scan %s did not complete within 2 minutes (last status: %s)", scanID, scan.Status)
		}
		time.Sleep(2 * time.Second)

		pollResp, err := httpClient.Do(authedReq(http.MethodGet, "/api/v1/scans/"+scanID, nil))
		if err != nil {
			t.Fatalf("poll scan request failed: %v", err)
		}
		pollRaw := readBody(t, pollResp)
		assertStatus(t, pollResp, http.StatusOK)

		if err := json.Unmarshal(pollRaw, &scan); err != nil {
			t.Fatalf("poll response is not valid JSON: %v\nbody: %s", err, pollRaw)
		}
		t.Logf("  poll: status=%s", scan.Status)

		switch scan.Status {
		case "completed", "done":
			goto scanDone
		case "failed", "error":
			t.Fatalf("scan %s failed; body: %s", scanID, pollRaw)
		}
	}
scanDone:

	// ── Step 4: Get findings ─────────────────────────────────────────────
	t.Log("Step 4: fetching findings")
	findingsResp, err := httpClient.Do(authedReq(http.MethodGet, "/api/v1/scans/"+scanID+"/findings", nil))
	if err != nil {
		t.Fatalf("get findings request failed: %v", err)
	}
	findingsRaw := readBody(t, findingsResp)
	assertStatus(t, findingsResp, http.StatusOK)
	assertContentType(t, findingsResp, "application/json")

	var findingsPayload map[string]interface{}
	if err := json.Unmarshal(findingsRaw, &findingsPayload); err != nil {
		// Try array format
		var arr []interface{}
		if err2 := json.Unmarshal(findingsRaw, &arr); err2 != nil {
			t.Fatalf("findings response is neither JSON object nor array: %v\nbody: %s", err, findingsRaw)
		}
		t.Logf("  findings: %d items (array format)", len(arr))
	} else {
		t.Logf("  findings: keys=%v", keys(findingsPayload))
	}

	// ── Step 5: Get report ───────────────────────────────────────────────
	t.Log("Step 5: fetching SARIF report")
	reportResp, err := httpClient.Do(authedReq(http.MethodGet, "/api/v1/scans/"+scanID+"/report?format=sarif", nil))
	if err != nil {
		t.Fatalf("get report request failed: %v", err)
	}
	reportRaw := readBody(t, reportResp)
	assertStatus(t, reportResp, http.StatusOK)

	var sarifDoc map[string]interface{}
	if err := json.Unmarshal(reportRaw, &sarifDoc); err != nil {
		t.Fatalf("SARIF report is not valid JSON: %v\nbody excerpt: %.500s", err, reportRaw)
	}
	// SARIF documents must have a "$schema" or "version" field.
	if _, ok := sarifDoc["$schema"]; !ok {
		if _, ok := sarifDoc["version"]; !ok {
			t.Errorf("SARIF report missing \"$schema\" and \"version\" fields; got keys: %v", keys(sarifDoc))
		}
	}
	t.Logf("  report: SARIF document received (%d bytes)", len(reportRaw))

	// ── Step 6: Delete scan ──────────────────────────────────────────────
	t.Log("Step 6: deleting scan")
	deleteResp, err := httpClient.Do(authedReq(http.MethodDelete, "/api/v1/scans/"+scanID, nil))
	if err != nil {
		t.Fatalf("delete scan request failed: %v", err)
	}
	readBody(t, deleteResp)
	assertStatus(t, deleteResp, http.StatusNoContent)
	t.Logf("  scan %s deleted successfully", scanID)

	// Verify scan is actually gone.
	verifyResp, err := httpClient.Do(authedReq(http.MethodGet, "/api/v1/scans/"+scanID, nil))
	if err != nil {
		t.Fatalf("verify deletion request failed: %v", err)
	}
	readBody(t, verifyResp)
	if verifyResp.StatusCode != http.StatusNotFound {
		t.Errorf("scan %s still exists after deletion: got HTTP %d, want 404", scanID, verifyResp.StatusCode)
	}
}

// keys returns the keys of a map[string]interface{} for use in error messages.
func keys(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// post is a convenience wrapper that performs a POST request with a JSON body
// and returns the response. The caller is responsible for closing resp.Body.
func post(t *testing.T, path string, body io.Reader) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s%s", baseURL(), path)
	resp, err := httpClient.Post(url, "application/json", body)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// TestCreateScan_InvalidSpecURL verifies that submitting a scan request whose
// spec_url resolves to a private IP address is rejected with HTTP 422 as part
// of SSRF protection.
func TestCreateScan_InvalidSpecURL(t *testing.T) {
	payload := `{"spec_url":"http://192.168.1.1/openapi.json","target":"http://192.168.1.1"}`
	resp := post(t, "/api/v1/scans", strings.NewReader(payload))
	readBody(t, resp)

	assertStatus(t, resp, http.StatusUnprocessableEntity)
}

// TestCreateScan_MissingTarget verifies that a scan creation request that
// includes a spec_url but omits the required target field is rejected with
// HTTP 422.
func TestCreateScan_MissingTarget(t *testing.T) {
	payload := `{"spec_url":"https://example.com/openapi.json"}`
	resp := post(t, "/api/v1/scans", strings.NewReader(payload))
	readBody(t, resp)

	assertStatus(t, resp, http.StatusUnprocessableEntity)
}

// TestListScans_Pagination verifies that the scan list endpoint accepts
// pagination query parameters and returns a response body with both a "data"
// array and a "total" field.
func TestListScans_Pagination(t *testing.T) {
	resp := get(t, "/api/v1/scans?page=1&per_page=5")
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, body)
	}

	if _, ok := payload["data"]; !ok {
		t.Errorf("pagination response missing \"data\" field; got keys: %v", keys(payload))
	}
	if _, ok := payload["total"]; !ok {
		t.Errorf("pagination response missing \"total\" field; got keys: %v", keys(payload))
	}
}

// TestGetScan_NotFound verifies that requesting a scan by a random UUID that
// does not exist returns HTTP 404.
func TestGetScan_NotFound(t *testing.T) {
	resp := get(t, "/api/v1/scans/00000000-0000-0000-0000-000000000000")
	readBody(t, resp)

	assertStatus(t, resp, http.StatusNotFound)
}

// TestFindings_RequiresAuth verifies that the findings endpoint rejects
// requests that do not carry a Bearer token with HTTP 401.
func TestFindings_RequiresAuth(t *testing.T) {
	url := fmt.Sprintf("%s/api/v1/findings", baseURL())
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	// Deliberately omit Authorization header.
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/findings without auth: got %d, want %d",
			resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestMetrics_Endpoint verifies that the Prometheus metrics endpoint is
// reachable and returns a response body in the standard text exposition format
// (lines beginning with "# HELP" or "# TYPE").
func TestMetrics_Endpoint(t *testing.T) {
	resp := get(t, "/metrics")
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "# HELP") && !strings.Contains(bodyStr, "# TYPE") {
		t.Errorf("metrics body does not look like Prometheus text format (missing \"# HELP\" / \"# TYPE\")\nbody excerpt: %.200s", bodyStr)
	}
}

// TestAuditLog_RequiresAuth verifies that the audit log endpoint rejects
// requests that do not carry a Bearer token with HTTP 401.
func TestAuditLog_RequiresAuth(t *testing.T) {
	url := fmt.Sprintf("%s/api/v1/audit", baseURL())
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	// Deliberately omit Authorization header.
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/audit without auth: got %d, want %d",
			resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestAPIVersion_Header verifies that every response from the API carries an
// X-API-Version header so that clients can detect version skew.
func TestAPIVersion_Header(t *testing.T) {
	resp := get(t, "/api/v1/health")
	readBody(t, resp)

	header := resp.Header.Get("X-API-Version")
	if header == "" {
		// Also check the lowercase variant in case the server uses a different
		// canonical form.
		header = resp.Header.Get("X-Api-Version")
	}
	if header == "" {
		t.Errorf("response is missing X-API-Version header")
	}
}
