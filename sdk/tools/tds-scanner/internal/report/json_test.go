package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/opensecstack/tds-scanner/internal/checks"
)

func sampleFindings() []checks.Finding {
	return []checks.Finding{
		{CheckID: "TDS-AUTH-001", Title: "Hardcoded Key", Severity: "critical", FilePath: "main.go", Line: 5, Column: 3, Snippet: `api_key = "abc"`, Remediation: "Use env var"},
		{CheckID: "TDS-TLS-002", Title: "HTTP URL", Severity: "high", FilePath: "client.go", Line: 12, Column: 1, Snippet: `url = "http://..."`, Remediation: "Use HTTPS"},
		{CheckID: "TDS-HDR-001", Title: "Missing X-Request-ID", Severity: "medium", FilePath: "client.go", Line: 8, Column: 1},
		{CheckID: "TDS-RETRY-002", Title: "Fixed Sleep", Severity: "low", FilePath: "retry.go", Line: 20, Column: 2},
	}
}

func TestWriteJSON_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, "./src", "go", 4, sampleFindings(), "fail")
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
}

func TestWriteJSON_SchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, ".", "go", 0, nil, "pass")
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	if report["schema_version"] != "1.0" {
		t.Errorf("expected schema_version=1.0, got %v", report["schema_version"])
	}
}

func TestWriteJSON_Target(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, "/my/project", "python", 0, nil, "pass")
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	if report["target"] != "/my/project" {
		t.Errorf("expected target=/my/project, got %v", report["target"])
	}
}

func TestWriteJSON_ChecksRun(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, ".", "go", 7, nil, "pass")
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	if report["checks_run"] != float64(7) {
		t.Errorf("expected checks_run=7, got %v", report["checks_run"])
	}
}

func TestWriteJSON_FindingsCount(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, ".", "go", 4, sampleFindings(), "fail")
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	findings := report["findings"].([]any)
	if len(findings) != 4 {
		t.Errorf("expected 4 findings in JSON, got %d", len(findings))
	}
}

func TestWriteJSON_SummaryCounts(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, ".", "go", 4, sampleFindings(), "fail")
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	summary := report["summary"].(map[string]any)
	if summary["critical"] != float64(1) {
		t.Errorf("expected critical=1, got %v", summary["critical"])
	}
	if summary["high"] != float64(1) {
		t.Errorf("expected high=1, got %v", summary["high"])
	}
	if summary["medium"] != float64(1) {
		t.Errorf("expected medium=1, got %v", summary["medium"])
	}
	if summary["low"] != float64(1) {
		t.Errorf("expected low=1, got %v", summary["low"])
	}
	if summary["info"] != float64(0) {
		t.Errorf("expected info=0, got %v", summary["info"])
	}
}

func TestWriteJSON_ResultField(t *testing.T) {
	for _, result := range []string{"pass", "fail"} {
		var buf bytes.Buffer
		_ = WriteJSON(&buf, ".", "go", 0, nil, result)
		var report map[string]any
		json.Unmarshal(buf.Bytes(), &report)
		if report["result"] != result {
			t.Errorf("expected result=%q, got %v", result, report["result"])
		}
	}
}

func TestWriteJSON_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, ".", "go", 3, nil, "pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	findings := report["findings"].([]any)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestWriteJSON_FindingFields(t *testing.T) {
	finding := checks.Finding{
		CheckID:     "TDS-AUTH-001",
		Title:       "Test Title",
		Description: "Test Description",
		Severity:    "critical",
		FilePath:    "main.go",
		Line:        42,
		Column:      7,
		Snippet:     "bad code",
		Remediation: "fix it",
	}
	var buf bytes.Buffer
	_ = WriteJSON(&buf, ".", "go", 1, []checks.Finding{finding}, "fail")
	var report map[string]any
	json.Unmarshal(buf.Bytes(), &report)
	f := report["findings"].([]any)[0].(map[string]any)
	if f["check_id"] != "TDS-AUTH-001" {
		t.Errorf("expected check_id=TDS-AUTH-001, got %v", f["check_id"])
	}
	if f["line"] != float64(42) {
		t.Errorf("expected line=42, got %v", f["line"])
	}
	if f["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %v", f["severity"])
	}
}
