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

// TestFullScanWorkflow is a stub for an end-to-end scan test that requires a
// live target service and a configured API key. Run with:
//
//	APIGUARD_TEST_URL=http://... APIGUARD_API_KEY=... go test -tags e2e ./tests/e2e/...
func TestFullScanWorkflow(t *testing.T) {
	t.Skip("requires live scan target: set APIGUARD_TEST_URL and APIGUARD_API_KEY")

	// TODO: implement full workflow:
	//   1. Exchange APIGUARD_API_KEY for a JWT via POST /api/v1/auth/token
	//   2. POST /api/v1/scans with a target URL to create a scan
	//   3. Poll GET /api/v1/scans/{id} until status is "completed" or timeout
	//   4. GET /api/v1/scans/{id}/findings and assert expected findings count
	//   5. GET /api/v1/scans/{id}/report and assert report format
	//   6. DELETE /api/v1/scans/{id} and assert 204
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
