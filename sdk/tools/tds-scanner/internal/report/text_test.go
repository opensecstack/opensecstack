package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/opensecstack/tds-scanner/internal/checks"
)

func TestWriteText_NoError(t *testing.T) {
	var buf bytes.Buffer
	err := WriteText(&buf, "./src", "go", 4, nil, "medium", "pass")
	if err != nil {
		t.Fatalf("WriteText returned error: %v", err)
	}
}

func TestWriteText_ContainsHeader(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteText(&buf, "./src", "go", 4, nil, "medium", "pass")
	out := buf.String()
	if !strings.Contains(out, "TDS Scanner Results") {
		t.Errorf("expected header 'TDS Scanner Results' in output\n%s", out)
	}
}

func TestWriteText_ContainsTarget(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteText(&buf, "/my/project", "python", 3, nil, "low", "pass")
	out := buf.String()
	if !strings.Contains(out, "/my/project") {
		t.Errorf("expected target path in output\n%s", out)
	}
}

func TestWriteText_ContainsLanguage(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteText(&buf, ".", "rust", 5, nil, "medium", "pass")
	out := buf.String()
	if !strings.Contains(out, "rust") {
		t.Errorf("expected language 'rust' in output\n%s", out)
	}
}

func TestWriteText_NoFindings_ShowsMessage(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteText(&buf, ".", "go", 4, nil, "medium", "pass")
	out := buf.String()
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' message when findings list is empty\n%s", out)
	}
}

func TestWriteText_FindingsListed(t *testing.T) {
	findings := []checks.Finding{
		{
			CheckID:     "TDS-AUTH-001",
			Title:       "Hardcoded API Key",
			Severity:    "critical",
			FilePath:    "main.go",
			Line:        10,
			Snippet:     `api_key = "abc123"`,
			Remediation: "Use env vars",
		},
	}
	var buf bytes.Buffer
	_ = WriteText(&buf, ".", "go", 4, findings, "medium", "fail")
	out := buf.String()

	if !strings.Contains(out, "TDS-AUTH-001") {
		t.Errorf("expected check ID in output\n%s", out)
	}
	if !strings.Contains(out, "Hardcoded API Key") {
		t.Errorf("expected title in output\n%s", out)
	}
	if !strings.Contains(out, "main.go:10") {
		t.Errorf("expected file:line reference in output\n%s", out)
	}
	if !strings.Contains(out, "Use env vars") {
		t.Errorf("expected remediation in output\n%s", out)
	}
}

func TestWriteText_SeverityLabel(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"critical", "[CRITICAL]"},
		{"high", "[HIGH]"},
		{"medium", "[MEDIUM]"},
		{"low", "[LOW]"},
	}
	for _, tc := range cases {
		t.Run(tc.severity, func(t *testing.T) {
			if got := severityLabel(tc.severity); got != tc.want {
				t.Errorf("severityLabel(%q) = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

func TestWriteText_SummaryCounts(t *testing.T) {
	findings := []checks.Finding{
		{Severity: "critical"},
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "medium"},
	}
	var buf bytes.Buffer
	_ = WriteText(&buf, ".", "go", 4, findings, "low", "fail")
	out := buf.String()
	if !strings.Contains(out, "Critical: 2") {
		t.Errorf("expected 'Critical: 2' in summary\n%s", out)
	}
	if !strings.Contains(out, "High: 1") {
		t.Errorf("expected 'High: 1' in summary\n%s", out)
	}
}

func TestWriteText_ResultPass(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteText(&buf, ".", "go", 4, nil, "medium", "pass")
	out := buf.String()
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS in result line\n%s", out)
	}
}

func TestWriteText_ResultFail(t *testing.T) {
	findings := []checks.Finding{{Severity: "critical", CheckID: "TDS-AUTH-001", FilePath: "f.go", Line: 1}}
	var buf bytes.Buffer
	_ = WriteText(&buf, ".", "go", 4, findings, "medium", "fail")
	out := buf.String()
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL in result line\n%s", out)
	}
}

func TestSummaryCounts_AllSeverities(t *testing.T) {
	findings := []checks.Finding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "info"},
		{Severity: "unknown"}, // should not appear in counts
	}
	counts := summaryCounts(findings)
	if counts["critical"] != 1 {
		t.Errorf("expected critical=1, got %d", counts["critical"])
	}
	if counts["high"] != 2 {
		t.Errorf("expected high=2, got %d", counts["high"])
	}
	if counts["medium"] != 1 {
		t.Errorf("expected medium=1, got %d", counts["medium"])
	}
	if counts["low"] != 1 {
		t.Errorf("expected low=1, got %d", counts["low"])
	}
	if counts["info"] != 1 {
		t.Errorf("expected info=1, got %d", counts["info"])
	}
}
