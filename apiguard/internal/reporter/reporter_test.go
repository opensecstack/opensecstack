package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
)

// testResult returns a representative ScanResult for use in tests.
func testResult() *domain.ScanResult {
	now := time.Date(2026, 3, 24, 14, 0, 0, 0, time.UTC)
	return &domain.ScanResult{
		ID:       "test-scan-001",
		Status:   domain.ScanStatusCompleted,
		Target:   "https://api.example.com",
		SpecHash: "sha256:abc123",
		Findings: []domain.Finding{
			{
				ID:             "f-001",
				ScanID:         "test-scan-001",
				OWASPId:        "API1:2023",
				ModuleID:       "a1_bola",
				Title:          "BOLA: Horizontal access to user profile",
				Description:    "User A can access User B's profile.",
				Severity:       domain.SeverityCritical,
				CVSSScore:      9.1,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				EndpointPath:   "/api/v1/users/{id}/profile",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /api/v1/users/1002/profile HTTP/1.1\nHost: api.example.com",
					Response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1002}",
				},
				Remediation: "Implement object-level authorisation checks.",
				Status:      domain.FindingStatusOpen,
			},
			{
				ID:             "f-002",
				ScanID:         "test-scan-001",
				OWASPId:        "API8:2023",
				ModuleID:       "a8_misconfig",
				Title:          "Missing security headers",
				Description:    "Several security headers are absent.",
				Severity:       domain.SeverityMedium,
				CVSSScore:      5.3,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				EndpointPath:   "/api/v1/health",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /api/v1/health HTTP/1.1",
					Response: "HTTP/1.1 200 OK",
				},
				Remediation: "Add X-Content-Type-Options, X-Frame-Options headers.",
				Status:      domain.FindingStatusOpen,
			},
		},
		Summary: domain.ScanSummary{
			TotalFindings: 2,
			Critical:      1,
			High:          0,
			Medium:        1,
			Low:           0,
			Info:          0,
		},
		StartedAt:   now,
		CompletedAt: now.Add(30 * time.Second),
	}
}

// --- Factory tests ---

func TestNew_SupportedFormats(t *testing.T) {
	for _, format := range []string{"json", "sarif", "html"} {
		r, err := New(format)
		if err != nil {
			t.Errorf("New(%q) returned error: %v", format, err)
		}
		if r == nil {
			t.Errorf("New(%q) returned nil reporter", format)
		}
	}
}

func TestNew_UnsupportedFormat(t *testing.T) {
	_, err := New("pdf")
	if err == nil {
		t.Error("New(\"pdf\") should return an error for unsupported format")
	}
}

// --- JSON reporter tests ---

func TestJSONReporter_Generate(t *testing.T) {
	r := &JSONReporter{}
	data, err := r.Generate(testResult())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Check top-level keys exist.
	for _, key := range []string{"scan", "summary", "findings", "metadata"} {
		if _, ok := report[key]; !ok {
			t.Errorf("JSON report missing top-level key %q", key)
		}
	}

	// Check scan fields.
	scan := report["scan"].(map[string]interface{})
	if scan["id"] != "test-scan-001" {
		t.Errorf("scan.id = %v, want test-scan-001", scan["id"])
	}
	if scan["target"] != "https://api.example.com" {
		t.Errorf("scan.target = %v, want https://api.example.com", scan["target"])
	}

	// Check summary counts.
	summary := report["summary"].(map[string]interface{})
	if int(summary["total"].(float64)) != 2 {
		t.Errorf("summary.total = %v, want 2", summary["total"])
	}
	if int(summary["critical"].(float64)) != 1 {
		t.Errorf("summary.critical = %v, want 1", summary["critical"])
	}

	// Check findings array length.
	findings := report["findings"].([]interface{})
	if len(findings) != 2 {
		t.Errorf("findings length = %d, want 2", len(findings))
	}

	// Check first finding severity is uppercase.
	f0 := findings[0].(map[string]interface{})
	if f0["severity"] != "CRITICAL" {
		t.Errorf("findings[0].severity = %v, want CRITICAL", f0["severity"])
	}
}

func TestJSONReporter_EmptyFindings(t *testing.T) {
	r := &JSONReporter{}
	result := testResult()
	result.Findings = nil
	result.Summary = domain.ScanSummary{}

	data, err := r.Generate(result)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	findings := report["findings"].([]interface{})
	if len(findings) != 0 {
		t.Errorf("findings length = %d, want 0", len(findings))
	}
}

// --- SARIF reporter tests ---

func TestSARIFReporter_Generate(t *testing.T) {
	r := &SARIFReporter{}
	data, err := r.Generate(testResult())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Check SARIF version.
	if sarif["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", sarif["version"])
	}

	// Check schema.
	schema := sarif["$schema"].(string)
	if !strings.Contains(schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema = %v, want sarif-schema-2.1.0 URI", schema)
	}

	// Check runs array.
	runs := sarif["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("runs length = %d, want 1", len(runs))
	}

	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})

	if driver["name"] != "APIGuard" {
		t.Errorf("driver.name = %v, want APIGuard", driver["name"])
	}

	// Check rules exist.
	rules := driver["rules"].([]interface{})
	if len(rules) == 0 {
		t.Error("driver.rules is empty, expected at least one rule")
	}

	// Check results.
	results := run["results"].([]interface{})
	if len(results) != 2 {
		t.Errorf("results length = %d, want 2", len(results))
	}

	// Check severity mapping: critical -> error.
	r0 := results[0].(map[string]interface{})
	if r0["level"] != "error" {
		t.Errorf("results[0].level = %v, want error", r0["level"])
	}

	// Check severity mapping: medium -> warning.
	r1 := results[1].(map[string]interface{})
	if r1["level"] != "warning" {
		t.Errorf("results[1].level = %v, want warning", r1["level"])
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity domain.Severity
		want     string
	}{
		{domain.SeverityCritical, "error"},
		{domain.SeverityHigh, "error"},
		{domain.SeverityMedium, "warning"},
		{domain.SeverityLow, "note"},
		{domain.SeverityInfo, "note"},
	}
	for _, tc := range tests {
		got := severityToSARIFLevel(tc.severity)
		if got != tc.want {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

// --- HTML reporter tests ---

func TestHTMLReporter_Generate(t *testing.T) {
	r := &HTMLReporter{}
	data, err := r.Generate(testResult())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	html := string(data)

	// Check it is a complete HTML document.
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("HTML output missing closing html tag")
	}

	// Check target appears.
	if !strings.Contains(html, "https://api.example.com") {
		t.Error("HTML output missing target URL")
	}

	// Check finding title appears.
	if !strings.Contains(html, "BOLA: Horizontal access to user profile") {
		t.Error("HTML output missing finding title")
	}

	// Check severity badge.
	if !strings.Contains(html, "CRITICAL") {
		t.Error("HTML output missing CRITICAL severity")
	}

	// Check inline CSS is present.
	if !strings.Contains(html, "<style>") {
		t.Error("HTML output missing inline CSS")
	}
}

func TestHTMLReporter_EmptyFindings(t *testing.T) {
	r := &HTMLReporter{}
	result := testResult()
	result.Findings = nil
	result.Summary = domain.ScanSummary{}

	data, err := r.Generate(result)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "No findings were detected") {
		t.Error("HTML output should show 'no findings' message when findings are empty")
	}
}
