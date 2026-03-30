//go:build fp

package fp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// httpClient is a shared client with a sensible timeout for false-positive tests.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// targetURL returns the known-safe target URL from the environment or defaults
// to localhost. Set FP_TARGET_URL to run against a different deployment.
func targetURL() string {
	if u := os.Getenv("FP_TARGET_URL"); u != "" {
		return u
	}
	return "http://localhost:8080" // default: test against APIGuard itself
}

// get performs a GET request against the target and returns the response.
// The caller is responsible for closing resp.Body.
func get(t *testing.T, path string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s%s", targetURL(), path)
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

// sensitivePatterns holds compiled regular expressions that should never appear
// in a response from a known-safe, unauthenticated endpoint.
var sensitivePatterns = []*regexp.Regexp{
	// Private key material
	regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	// Raw JWT-shaped tokens (three base64url segments separated by dots)
	regexp.MustCompile(`[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
	// AWS-style access key IDs
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	// Password fields in plaintext JSON
	regexp.MustCompile(`(?i)"password"\s*:\s*"[^"]{1,}"`),
	// Secret / api_key fields in plaintext JSON
	regexp.MustCompile(`(?i)"(secret|api_key|apikey)"\s*:\s*"[^"]{8,}"`),
}

// assertNoSensitiveData fails the test if the response body matches any known
// sensitive-data pattern.
func assertNoSensitiveData(t *testing.T, body []byte) {
	t.Helper()
	for _, re := range sensitivePatterns {
		if re.Match(body) {
			t.Errorf("response body matches sensitive data pattern %q", re.String())
		}
	}
}

// assertContentTypeJSON fails the test if the Content-Type header does not
// indicate JSON.
func assertContentTypeJSON(t *testing.T, resp *http.Response) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
}

// TestNoFalsePositivesOnHealthEndpoint verifies that the health endpoint
// behaves as a fully safe, public endpoint: returns 200, serves JSON, and
// does not leak any sensitive data.
func TestNoFalsePositivesOnHealthEndpoint(t *testing.T) {
	resp := get(t, "/api/v1/health")
	body := readBody(t, resp)

	// A false-positive auth scanner might flag 401/403 as an auth bypass or
	// highlight that no token is required — assert the endpoint is intentionally
	// public and returns 200.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health endpoint: got status %d, want %d — endpoint should be public (no auth required)",
			resp.StatusCode, http.StatusOK)
	}

	assertContentTypeJSON(t, resp)

	// Validate the response is parseable, well-formed JSON.
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("health response is not valid JSON: %v\nbody: %s", err, body)
	}

	// The health response must contain "status": "ok" — any other value would
	// indicate a degraded service which a scanner might flag as anomalous.
	status, _ := payload["status"].(string)
	if status != "ok" {
		t.Errorf("health status: got %q, want \"ok\"", status)
	}

	// No sensitive data should be present in a public status endpoint.
	assertNoSensitiveData(t, body)
}

// TestNoFalsePositivesOnVersionEndpoint verifies that the version endpoint
// does not expose sensitive build-time information that a scanner might flag
// as an information-disclosure finding.
func TestNoFalsePositivesOnVersionEndpoint(t *testing.T) {
	resp := get(t, "/api/v1/version")
	body := readBody(t, resp)

	// Public endpoint — must not require auth.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("version endpoint: got status %d, want %d — endpoint should be public",
			resp.StatusCode, http.StatusOK)
	}

	assertContentTypeJSON(t, resp)

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("version response is not valid JSON: %v\nbody: %s", err, body)
	}

	// Allowed fields in a version response — anything beyond these could be
	// flagged by a scanner as unnecessary information disclosure.
	allowedFields := map[string]bool{
		"version":    true,
		"git_commit": true,
		"build_date": true,
		"go_version": true,
		"os":         true,
		"arch":       true,
	}
	for field := range payload {
		if !allowedFields[field] {
			t.Errorf("version response contains unexpected field %q — may be flagged as information disclosure", field)
		}
	}

	// Version responses must never contain credentials or key material.
	assertNoSensitiveData(t, body)
}

// TestNoFalsePositivesOnOpenAPISpec verifies that the embedded OpenAPI
// specification does not contain patterns that would cause a scanner to raise
// spurious security findings (e.g. example values that look like real secrets).
func TestNoFalsePositivesOnOpenAPISpec(t *testing.T) {
	resp := get(t, "/api/v1/openapi.json")
	body := readBody(t, resp)

	// Public endpoint — must not require auth.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("openapi.json: got status %d, want %d — endpoint should be public",
			resp.StatusCode, http.StatusOK)
	}

	assertContentTypeJSON(t, resp)

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v\nbody: %s", err, body)
	}

	// Must be a recognisable OpenAPI document.
	if _, hasV3 := payload["openapi"]; !hasV3 {
		if _, hasV2 := payload["swagger"]; !hasV2 {
			t.Error("openapi.json does not contain an \"openapi\" or \"swagger\" version field")
		}
	}

	// Example JWT values inside the spec (e.g. in 'example' fields) are a known
	// source of false positives — a scanner might extract them and attempt replay.
	// We check that no three-segment JWT-shaped strings appear in the raw document,
	// except for obviously placeholder strings.
	jwtRe := regexp.MustCompile(`[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`)
	if matches := jwtRe.FindAll(body, -1); len(matches) > 0 {
		t.Errorf("openapi.json contains %d JWT-shaped string(s) that may cause false-positive findings: %s",
			len(matches), matches[0])
	}

	// Private key material must never appear in a spec file.
	pkRe := regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	if pkRe.Match(body) {
		t.Error("openapi.json contains private key material")
	}
}
