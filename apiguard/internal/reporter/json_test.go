package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
)

// jsonScanResult builds a ScanResult with three findings of distinct severities
// so that summary counts and modules_enabled can be verified precisely.
func jsonScanResult() *domain.ScanResult {
	base := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	return &domain.ScanResult{
		ID:       "json-scan-001",
		Status:   domain.ScanStatusCompleted,
		Target:   "https://api.acme.com/v2",
		SpecHash: "sha256:deadbeef",
		Findings: []domain.Finding{
			{
				ID:             "jf-001",
				ScanID:         "json-scan-001",
				OWASPId:        "API1:2023",
				ModuleID:       "a1_bola",
				Title:          "BOLA on orders endpoint",
				Description:    "Attacker can read other users' orders.",
				Severity:       domain.SeverityCritical,
				CVSSScore:      9.8,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				EndpointPath:   "/v2/orders/{id}",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /v2/orders/9999 HTTP/1.1",
					Response: "HTTP/1.1 200 OK",
				},
				Remediation: "Check ownership before returning the resource.",
				Status:      domain.FindingStatusOpen,
			},
			{
				ID:             "jf-002",
				ScanID:         "json-scan-001",
				OWASPId:        "API2:2023",
				ModuleID:       "a2_auth",
				Title:          "Weak JWT algorithm",
				Description:    "Server accepts tokens signed with HS256.",
				Severity:       domain.SeverityHigh,
				CVSSScore:      8.1,
				CVSSVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
				EndpointPath:   "/v2/auth/token",
				EndpointMethod: "POST",
				Evidence: domain.Evidence{
					Request:  "POST /v2/auth/token HTTP/1.1",
					Response: "HTTP/1.1 200 OK\n{\"token\":\"eyJ...\"}",
				},
				Remediation: "Enforce RS256 or ES256 only.",
				Status:      domain.FindingStatusConfirmed,
			},
			{
				ID:             "jf-003",
				ScanID:         "json-scan-001",
				OWASPId:        "API4:2023",
				ModuleID:       "a4_rate_limit",
				Title:          "No rate limiting on /v2/search",
				Description:    "Endpoint responds to unlimited requests.",
				Severity:       domain.SeverityMedium,
				CVSSScore:      5.3,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
				EndpointPath:   "/v2/search",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /v2/search?q=test HTTP/1.1",
					Response: "HTTP/1.1 200 OK",
				},
				Remediation: "Apply a per-IP rate limit.",
				Status:      domain.FindingStatusOpen,
			},
		},
		Summary: domain.ScanSummary{
			TotalFindings: 3,
			Critical:      1,
			High:          1,
			Medium:        1,
			Low:           0,
			Info:          0,
		},
		StartedAt:   base,
		CompletedAt: base.Add(45 * time.Second),
	}
}

// helper: unmarshal Generate output into a generic map.
func generateJSON(t *testing.T, result *domain.ScanResult) map[string]interface{} {
	t.Helper()
	r := &JSONReporter{}
	data, err := r.Generate(result)
	if err != nil {
		t.Fatalf("JSONReporter.Generate returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("JSONReporter output is not valid JSON: %v", err)
	}
	return out
}

// TestJSONReporter_ValidJSON verifies that Generate always returns parseable JSON.
func TestJSONReporter_ValidJSON(t *testing.T) {
	r := &JSONReporter{}
	data, err := r.Generate(jsonScanResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
}

// TestJSONReporter_TopLevelKeys ensures all required top-level keys are present.
func TestJSONReporter_TopLevelKeys(t *testing.T) {
	report := generateJSON(t, jsonScanResult())
	for _, key := range []string{"scan", "summary", "findings", "metadata"} {
		if _, ok := report[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
}

// TestJSONReporter_ScanMetadata verifies scan block fields.
func TestJSONReporter_ScanMetadata(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	scan, ok := report["scan"].(map[string]interface{})
	if !ok {
		t.Fatal("scan key is not an object")
	}

	checks := map[string]string{
		"id":        result.ID,
		"target":    result.Target,
		"status":    string(result.Status),
		"spec_hash": result.SpecHash,
	}
	for field, want := range checks {
		if got, _ := scan[field].(string); got != want {
			t.Errorf("scan.%s = %q, want %q", field, got, want)
		}
	}

	// started_at and completed_at must be RFC3339 strings.
	for _, field := range []string{"started_at", "completed_at"} {
		v, _ := scan[field].(string)
		if v == "" {
			t.Errorf("scan.%s is empty", field)
		}
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			t.Errorf("scan.%s = %q is not RFC3339: %v", field, v, err)
		}
	}
}

// TestJSONReporter_SummaryCounts checks that severity counts match the input.
func TestJSONReporter_SummaryCounts(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	summary, ok := report["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("summary key is not an object")
	}

	intField := func(key string) int { return int(summary[key].(float64)) }

	if got := intField("total"); got != result.Summary.TotalFindings {
		t.Errorf("summary.total = %d, want %d", got, result.Summary.TotalFindings)
	}
	if got := intField("critical"); got != result.Summary.Critical {
		t.Errorf("summary.critical = %d, want %d", got, result.Summary.Critical)
	}
	if got := intField("high"); got != result.Summary.High {
		t.Errorf("summary.high = %d, want %d", got, result.Summary.High)
	}
	if got := intField("medium"); got != result.Summary.Medium {
		t.Errorf("summary.medium = %d, want %d", got, result.Summary.Medium)
	}
	if got := intField("low"); got != result.Summary.Low {
		t.Errorf("summary.low = %d, want %d", got, result.Summary.Low)
	}
	if got := intField("info"); got != result.Summary.Info {
		t.Errorf("summary.info = %d, want %d", got, result.Summary.Info)
	}
}

// TestJSONReporter_FindingsArray verifies that the findings array has the right
// length and that each entry has expected fields.
func TestJSONReporter_FindingsArray(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	raw, ok := report["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not a JSON array")
	}
	if len(raw) != len(result.Findings) {
		t.Fatalf("findings length = %d, want %d", len(raw), len(result.Findings))
	}

	required := []string{"id", "owasp_id", "module_id", "title", "severity",
		"cvss_score", "endpoint", "method", "remediation", "status"}
	for i, item := range raw {
		f, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("findings[%d] is not an object", i)
		}
		for _, key := range required {
			if _, ok := f[key]; !ok {
				t.Errorf("findings[%d] missing key %q", i, key)
			}
		}
	}
}

// TestJSONReporter_SeverityUpperCase checks that every severity value is
// upper-cased in the output.
func TestJSONReporter_SeverityUpperCase(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	raw := report["findings"].([]interface{})
	for i, item := range raw {
		f := item.(map[string]interface{})
		sev, _ := f["severity"].(string)
		if sev != strings.ToUpper(sev) {
			t.Errorf("findings[%d].severity = %q, want upper-case", i, sev)
		}
	}
}

// TestJSONReporter_FindingSeverityValues verifies that the three distinct
// severities are represented with the correct upper-case values.
func TestJSONReporter_FindingSeverityValues(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	raw := report["findings"].([]interface{})
	wantSeverities := []string{"CRITICAL", "HIGH", "MEDIUM"}
	for i, want := range wantSeverities {
		f := raw[i].(map[string]interface{})
		if got := f["severity"].(string); got != want {
			t.Errorf("findings[%d].severity = %q, want %q", i, got, want)
		}
	}
}

// TestJSONReporter_ModulesEnabled verifies that modules_enabled contains the
// unique module IDs referenced by findings, with no duplicates.
func TestJSONReporter_ModulesEnabled(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	summary := report["summary"].(map[string]interface{})
	modsRaw, ok := summary["modules_enabled"].([]interface{})
	if !ok {
		t.Fatal("summary.modules_enabled is not an array")
	}

	// Should have exactly one entry per unique module referenced in findings.
	wantModules := map[string]bool{
		"a1_bola":       false,
		"a2_auth":       false,
		"a4_rate_limit": false,
	}
	for _, m := range modsRaw {
		id, _ := m.(string)
		if _, expected := wantModules[id]; expected {
			wantModules[id] = true
		}
	}
	for id, seen := range wantModules {
		if !seen {
			t.Errorf("modules_enabled: expected module %q not found", id)
		}
	}

	// No duplicate module IDs.
	seen := make(map[string]int)
	for _, m := range modsRaw {
		id, _ := m.(string)
		seen[id]++
		if seen[id] > 1 {
			t.Errorf("modules_enabled: duplicate module ID %q", id)
		}
	}
}

// TestJSONReporter_MetadataFields ensures the metadata block contains
// apiguard_version, scan_duration, and report_generated_at.
func TestJSONReporter_MetadataFields(t *testing.T) {
	report := generateJSON(t, jsonScanResult())

	meta, ok := report["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata key is not an object")
	}
	for _, key := range []string{"apiguard_version", "scan_duration", "report_generated_at"} {
		v, _ := meta[key].(string)
		if v == "" {
			t.Errorf("metadata.%s is empty or missing", key)
		}
	}

	// report_generated_at must be a valid RFC3339 timestamp.
	ts, _ := meta["report_generated_at"].(string)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("metadata.report_generated_at = %q is not RFC3339: %v", ts, err)
	}
}

// TestJSONReporter_EmptyFindingsProducesArray verifies that with no findings
// the output still produces a JSON array (not null).
func TestJSONReporter_EmptyFindingsProducesArray(t *testing.T) {
	result := jsonScanResult()
	result.Findings = []domain.Finding{}
	result.Summary = domain.ScanSummary{}

	report := generateJSON(t, result)

	raw, ok := report["findings"].([]interface{})
	if !ok {
		t.Fatal("findings with empty slice should still produce a JSON array")
	}
	if len(raw) != 0 {
		t.Errorf("findings length = %d, want 0", len(raw))
	}
}

// TestJSONReporter_EvidenceFields checks that evidence request/response are
// included for each finding.
func TestJSONReporter_EvidenceFields(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	raw := report["findings"].([]interface{})
	for i, item := range raw {
		f := item.(map[string]interface{})
		ev, ok := f["evidence"].(map[string]interface{})
		if !ok {
			t.Errorf("findings[%d].evidence is not an object", i)
			continue
		}
		for _, key := range []string{"request", "response"} {
			if _, ok := ev[key]; !ok {
				t.Errorf("findings[%d].evidence missing key %q", i, key)
			}
		}
	}
}

// TestJSONReporter_FindingEndpointAndMethod verifies endpoint path and HTTP
// method are present and non-empty for each finding.
func TestJSONReporter_FindingEndpointAndMethod(t *testing.T) {
	result := jsonScanResult()
	report := generateJSON(t, result)

	raw := report["findings"].([]interface{})
	for i, item := range raw {
		f := item.(map[string]interface{})
		endpoint, _ := f["endpoint"].(string)
		method, _ := f["method"].(string)
		if endpoint == "" {
			t.Errorf("findings[%d].endpoint is empty", i)
		}
		if method == "" {
			t.Errorf("findings[%d].method is empty", i)
		}
	}
}

// TestJSONReporter_ScanDuration checks that the reported duration string
// matches the difference between CompletedAt and StartedAt.
func TestJSONReporter_ScanDuration(t *testing.T) {
	result := jsonScanResult()
	expected := result.CompletedAt.Sub(result.StartedAt).String()
	report := generateJSON(t, result)

	meta := report["metadata"].(map[string]interface{})
	got, _ := meta["scan_duration"].(string)
	if got != expected {
		t.Errorf("metadata.scan_duration = %q, want %q", got, expected)
	}
}
