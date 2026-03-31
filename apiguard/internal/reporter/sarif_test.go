package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
)

// sarifScanResult builds a ScanResult with three findings spanning three
// different OWASP modules, exercising multiple SARIF rule entries and result
// severity mappings.
func sarifScanResult() *domain.ScanResult {
	base := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	return &domain.ScanResult{
		ID:     "sarif-scan-001",
		Status: domain.ScanStatusCompleted,
		Target: "https://api.example.io/v1",
		Findings: []domain.Finding{
			{
				ID:             "sf-001",
				ScanID:         "sarif-scan-001",
				OWASPId:        "API1:2023",
				ModuleID:       "a1_bola",
				Title:          "BOLA: Unauthorised resource access",
				Description:    "Cross-user object access without authorisation.",
				Severity:       domain.SeverityCritical,
				CVSSScore:      9.1,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				EndpointPath:   "/v1/accounts/{id}",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /v1/accounts/777 HTTP/1.1",
					Response: "HTTP/1.1 200 OK",
				},
				Remediation: "Add per-object ownership checks.",
				Status:      domain.FindingStatusOpen,
			},
			{
				ID:             "sf-002",
				ScanID:         "sarif-scan-001",
				OWASPId:        "API5:2023",
				ModuleID:       "a5_function_auth",
				Title:          "Admin endpoint exposed without auth",
				Description:    "DELETE /v1/admin/users accessible without token.",
				Severity:       domain.SeverityHigh,
				CVSSScore:      7.5,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
				EndpointPath:   "/v1/admin/users",
				EndpointMethod: "DELETE",
				Evidence: domain.Evidence{
					Request:  "DELETE /v1/admin/users HTTP/1.1",
					Response: "HTTP/1.1 200 OK",
				},
				Remediation: "Require admin role on all /admin/* routes.",
				Status:      domain.FindingStatusOpen,
			},
			{
				ID:             "sf-003",
				ScanID:         "sarif-scan-001",
				OWASPId:        "API4:2023",
				ModuleID:       "a4_rate_limit",
				Title:          "No rate limit on public search",
				Description:    "Search endpoint allows unlimited requests.",
				Severity:       domain.SeverityLow,
				CVSSScore:      3.1,
				CVSSVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
				EndpointPath:   "/v1/search",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /v1/search?q=x HTTP/1.1",
					Response: "HTTP/1.1 200 OK",
				},
				Remediation: "Implement sliding-window rate limiting.",
				Status:      domain.FindingStatusOpen,
			},
		},
		Summary: domain.ScanSummary{
			TotalFindings: 3,
			Critical:      1,
			High:          1,
			Low:           1,
		},
		StartedAt:   base,
		CompletedAt: base.Add(20 * time.Second),
	}
}

// parseSARIF generates a SARIF report and unmarshals it into a generic map.
func parseSARIF(t *testing.T, result *domain.ScanResult) map[string]interface{} {
	t.Helper()
	r := &SARIFReporter{}
	data, err := r.Generate(result)
	if err != nil {
		t.Fatalf("SARIFReporter.Generate returned error: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("SARIFReporter output is not valid JSON")
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	return out
}

// extractSarifRun extracts the single run object from a parsed SARIF document.
func extractSarifRun(t *testing.T, doc map[string]interface{}) map[string]interface{} {
	t.Helper()
	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("runs is missing or empty")
	}
	run, ok := runs[0].(map[string]interface{})
	if !ok {
		t.Fatal("runs[0] is not an object")
	}
	return run
}

// TestSARIFReporter_ValidJSON checks that Generate returns parseable JSON.
func TestSARIFReporter_ValidJSON(t *testing.T) {
	r := &SARIFReporter{}
	data, err := r.Generate(sarifScanResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
}

// TestSARIFReporter_SchemaVersion verifies the SARIF version is "2.1.0".
func TestSARIFReporter_SchemaVersion(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())

	version, _ := doc["version"].(string)
	if version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", version)
	}
}

// TestSARIFReporter_SchemaURI checks that $schema references the 2.1.0 spec.
func TestSARIFReporter_SchemaURI(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())

	schema, _ := doc["$schema"].(string)
	if !strings.Contains(schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema = %q, want URI containing sarif-schema-2.1.0", schema)
	}
}

// TestSARIFReporter_RunsArray verifies exactly one run is produced.
func TestSARIFReporter_RunsArray(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())

	runs, ok := doc["runs"].([]interface{})
	if !ok {
		t.Fatal("runs is not an array")
	}
	if len(runs) != 1 {
		t.Errorf("runs length = %d, want 1", len(runs))
	}
}

// TestSARIFReporter_DriverName checks the tool driver name is "APIGuard".
func TestSARIFReporter_DriverName(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	name, _ := driver["name"].(string)
	if name != "APIGuard" {
		t.Errorf("driver.name = %q, want APIGuard", name)
	}
}

// TestSARIFReporter_DriverVersion checks that the driver version is non-empty.
func TestSARIFReporter_DriverVersion(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	ver, _ := driver["version"].(string)
	if ver == "" {
		t.Error("driver.version is empty")
	}
}

// TestSARIFReporter_RulesArrayPresent checks that rules is a non-empty array
// covering at least the default modules.
func TestSARIFReporter_RulesArrayPresent(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules, ok := driver["rules"].([]interface{})
	if !ok {
		t.Fatal("driver.rules is not an array")
	}
	// DefaultModules supplies 10 modules; each with a mapping should appear.
	if len(rules) == 0 {
		t.Error("driver.rules is empty")
	}
}

// TestSARIFReporter_RuleIDsNonEmpty ensures every rule has a non-empty id.
func TestSARIFReporter_RuleIDsNonEmpty(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})

	for i, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			t.Errorf("rules[%d] is not an object", i)
			continue
		}
		id, _ := rule["id"].(string)
		if id == "" {
			t.Errorf("rules[%d].id is empty", i)
		}
	}
}

// TestSARIFReporter_RuleIDsMatchMapping checks that the well-known module IDs
// produce the expected "apiguard/<slug>" rule IDs from sarifModuleMapping.
func TestSARIFReporter_RuleIDsMatchMapping(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})

	// Build a set of rule IDs present in the output.
	ruleIDs := make(map[string]bool)
	for _, item := range rules {
		rule := item.(map[string]interface{})
		if id, _ := rule["id"].(string); id != "" {
			ruleIDs[id] = true
		}
	}

	// The following well-known module IDs are present in DefaultModules AND have
	// entries in sarifModuleMapping, so they must appear as rules.
	expected := []string{
		"apiguard/a1-bola",
		"apiguard/a5-function-auth",
	}
	for _, wantID := range expected {
		if !ruleIDs[wantID] {
			t.Errorf("expected rule ID %q not found in rules array", wantID)
		}
	}
}

// TestSARIFReporter_ResultsCount checks that results length equals findings count.
func TestSARIFReporter_ResultsCount(t *testing.T) {
	result := sarifScanResult()
	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)

	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("run.results is not an array")
	}
	if len(results) != len(result.Findings) {
		t.Errorf("results length = %d, want %d", len(results), len(result.Findings))
	}
}

// TestSARIFReporter_ResultLevelMapping verifies the severity-to-SARIF-level
// mapping: critical -> error, high -> error, low -> note.
func TestSARIFReporter_ResultLevelMapping(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	// Findings are in order: critical, high, low.
	wantLevels := []string{"error", "error", "note"}
	for i, want := range wantLevels {
		r := results[i].(map[string]interface{})
		level, _ := r["level"].(string)
		if level != want {
			t.Errorf("results[%d].level = %q, want %q", i, level, want)
		}
	}
}

// TestSARIFReporter_ResultRuleIDPresent ensures every result has a ruleId.
func TestSARIFReporter_ResultRuleIDPresent(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	for i, item := range results {
		r, ok := item.(map[string]interface{})
		if !ok {
			t.Errorf("results[%d] is not an object", i)
			continue
		}
		ruleID, _ := r["ruleId"].(string)
		if ruleID == "" {
			t.Errorf("results[%d].ruleId is empty", i)
		}
	}
}

// TestSARIFReporter_LocationURIFormat verifies that each result location URI
// matches the corresponding finding's EndpointPath.
func TestSARIFReporter_LocationURIFormat(t *testing.T) {
	result := sarifScanResult()
	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	for i, item := range results {
		r := item.(map[string]interface{})
		locs, ok := r["locations"].([]interface{})
		if !ok || len(locs) == 0 {
			t.Errorf("results[%d].locations is missing or empty", i)
			continue
		}
		loc := locs[0].(map[string]interface{})
		phys := loc["physicalLocation"].(map[string]interface{})
		artifact := phys["artifactLocation"].(map[string]interface{})

		uri, _ := artifact["uri"].(string)
		wantURI := result.Findings[i].EndpointPath
		if uri != wantURI {
			t.Errorf("results[%d] location uri = %q, want %q", i, uri, wantURI)
		}
	}
}

// TestSARIFReporter_LocationURIBaseID checks that uriBaseId is set to "API_ROOT".
func TestSARIFReporter_LocationURIBaseID(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	for i, item := range results {
		r := item.(map[string]interface{})
		locs := r["locations"].([]interface{})
		loc := locs[0].(map[string]interface{})
		phys := loc["physicalLocation"].(map[string]interface{})
		artifact := phys["artifactLocation"].(map[string]interface{})

		baseID, _ := artifact["uriBaseId"].(string)
		if baseID != "API_ROOT" {
			t.Errorf("results[%d] uriBaseId = %q, want API_ROOT", i, baseID)
		}
	}
}

// TestSARIFReporter_LocationMethodProperty verifies the HTTP method is stored
// in the location's properties.method field.
func TestSARIFReporter_LocationMethodProperty(t *testing.T) {
	result := sarifScanResult()
	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	for i, item := range results {
		r := item.(map[string]interface{})
		locs := r["locations"].([]interface{})
		loc := locs[0].(map[string]interface{})
		props, ok := loc["properties"].(map[string]interface{})
		if !ok {
			t.Errorf("results[%d] location.properties is missing", i)
			continue
		}
		method, _ := props["method"].(string)
		wantMethod := result.Findings[i].EndpointMethod
		if method != wantMethod {
			t.Errorf("results[%d] location.properties.method = %q, want %q", i, method, wantMethod)
		}
	}
}

// TestSARIFReporter_ResultCVSSProperties verifies the CVSS score and vector
// are encoded in each result's properties.
func TestSARIFReporter_ResultCVSSProperties(t *testing.T) {
	result := sarifScanResult()
	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	for i, item := range results {
		r := item.(map[string]interface{})
		props, ok := r["properties"].(map[string]interface{})
		if !ok {
			t.Errorf("results[%d].properties is missing", i)
			continue
		}
		if _, ok := props["cvss_score"]; !ok {
			t.Errorf("results[%d].properties missing cvss_score", i)
		}
		if _, ok := props["cvss_vector"]; !ok {
			t.Errorf("results[%d].properties missing cvss_vector", i)
		}
	}
}

// TestSARIFReporter_RuleShortDescriptionPresent checks that every rule has a
// non-empty shortDescription.text.
func TestSARIFReporter_RuleShortDescriptionPresent(t *testing.T) {
	doc := parseSARIF(t, sarifScanResult())
	run := extractSarifRun(t, doc)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})

	for i, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		sd, ok := rule["shortDescription"].(map[string]interface{})
		if !ok {
			t.Errorf("rules[%d].shortDescription is missing or not an object", i)
			continue
		}
		text, _ := sd["text"].(string)
		if text == "" {
			t.Errorf("rules[%d].shortDescription.text is empty", i)
		}
	}
}

// TestSARIFReporter_InfoSeverityMapsToNote confirms that an info-severity
// finding produces a SARIF "note" level.
func TestSARIFReporter_InfoSeverityMapsToNote(t *testing.T) {
	result := &domain.ScanResult{
		ID:     "sarif-info-test",
		Status: domain.ScanStatusCompleted,
		Findings: []domain.Finding{
			{
				ID:             "sf-info",
				OWASPId:        "API9:2023",
				ModuleID:       "a9_inventory",
				Title:          "Undocumented endpoint detected",
				Severity:       domain.SeverityInfo,
				EndpointPath:   "/v1/internal/debug",
				EndpointMethod: "GET",
				Status:         domain.FindingStatusOpen,
			},
		},
		Summary:     domain.ScanSummary{TotalFindings: 1, Info: 1},
		StartedAt:   time.Now(),
		CompletedAt: time.Now().Add(5 * time.Second),
	}

	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	r := results[0].(map[string]interface{})
	level, _ := r["level"].(string)
	if level != "note" {
		t.Errorf("info severity: level = %q, want note", level)
	}
}

// TestSARIFReporter_MediumSeverityMapsToWarning confirms medium -> warning.
func TestSARIFReporter_MediumSeverityMapsToWarning(t *testing.T) {
	result := &domain.ScanResult{
		ID:     "sarif-medium-test",
		Status: domain.ScanStatusCompleted,
		Findings: []domain.Finding{
			{
				ID:             "sf-med",
				OWASPId:        "API8:2023",
				ModuleID:       "a8_misconfiguration",
				Title:          "Missing HSTS header",
				Severity:       domain.SeverityMedium,
				EndpointPath:   "/v1/login",
				EndpointMethod: "POST",
				Status:         domain.FindingStatusOpen,
			},
		},
		Summary:     domain.ScanSummary{TotalFindings: 1, Medium: 1},
		StartedAt:   time.Now(),
		CompletedAt: time.Now().Add(3 * time.Second),
	}

	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)
	results := run["results"].([]interface{})

	r := results[0].(map[string]interface{})
	level, _ := r["level"].(string)
	if level != "warning" {
		t.Errorf("medium severity: level = %q, want warning", level)
	}
}

// TestSARIFReporter_EmptyFindings checks that with no findings the output
// still has a valid SARIF structure with an empty results array.
func TestSARIFReporter_EmptyFindings(t *testing.T) {
	result := &domain.ScanResult{
		ID:          "sarif-empty-test",
		Status:      domain.ScanStatusCompleted,
		Findings:    nil,
		Summary:     domain.ScanSummary{},
		StartedAt:   time.Now(),
		CompletedAt: time.Now().Add(1 * time.Second),
	}

	doc := parseSARIF(t, result)
	run := extractSarifRun(t, doc)

	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("run.results is not an array")
	}
	if len(results) != 0 {
		t.Errorf("results length = %d, want 0 for empty findings", len(results))
	}
}
