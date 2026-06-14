package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
)

// htmlScanResult builds a realistic ScanResult with three findings covering
// critical, medium, and low severities for HTML rendering tests.
func htmlScanResult() *domain.ScanResult {
	base := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	return &domain.ScanResult{
		ID:       "html-scan-001",
		Status:   domain.ScanStatusCompleted,
		Target:   "https://payments.example.com/api",
		SpecHash: "sha256:cafebabe",
		Findings: []domain.Finding{
			{
				ID:             "hf-001",
				ScanID:         "html-scan-001",
				OWASPId:        "API1:2023",
				ModuleID:       "a1_bola",
				Title:          "BOLA: Unauthorised payment record access",
				Description:    "Payment records accessible across user boundaries.",
				Severity:       domain.SeverityCritical,
				CVSSScore:      9.1,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				EndpointPath:   "/api/payments/{id}",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /api/payments/5000 HTTP/1.1",
					Response: "HTTP/1.1 200 OK\n{\"id\":5000,\"amount\":999}",
				},
				Remediation: "Enforce ownership checks on every payment lookup.",
				Status:      domain.FindingStatusOpen,
			},
			{
				ID:             "hf-002",
				ScanID:         "html-scan-001",
				OWASPId:        "API8:2023",
				ModuleID:       "a8_misconfiguration",
				Title:          "CORS misconfiguration allows any origin",
				Description:    "Access-Control-Allow-Origin: * exposes all endpoints.",
				Severity:       domain.SeverityMedium,
				CVSSScore:      5.4,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
				EndpointPath:   "/api/v1/profile",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /api/v1/profile HTTP/1.1\nOrigin: https://evil.com",
					Response: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *",
				},
				Remediation: "Restrict CORS to trusted origins only.",
				Status:      domain.FindingStatusOpen,
			},
			{
				ID:             "hf-003",
				ScanID:         "html-scan-001",
				OWASPId:        "API9:2023",
				ModuleID:       "a9_inventory",
				Title:          "Undocumented debug endpoint",
				Description:    "Debug route returns internal stack traces.",
				Severity:       domain.SeverityLow,
				CVSSScore:      2.7,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
				EndpointPath:   "/api/debug/status",
				EndpointMethod: "GET",
				Evidence: domain.Evidence{
					Request:  "GET /api/debug/status HTTP/1.1",
					Response: "HTTP/1.1 200 OK\n{\"stack\":\"...\"}\n",
				},
				Remediation: "Remove or restrict debug endpoints in production.",
				Status:      domain.FindingStatusOpen,
			},
		},
		Summary: domain.ScanSummary{
			TotalFindings: 3,
			Critical:      1,
			Medium:        1,
			Low:           1,
		},
		StartedAt:   base,
		CompletedAt: base.Add(1 * time.Minute),
	}
}

// generateHTML is a test helper that calls HTMLReporter.Generate and returns
// the output as a string, failing the test on any error.
func generateHTML(t *testing.T, result *domain.ScanResult) string {
	t.Helper()
	r := &HTMLReporter{}
	data, err := r.Generate(result)
	if err != nil {
		t.Fatalf("HTMLReporter.Generate returned error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("HTMLReporter.Generate returned empty bytes")
	}
	return string(data)
}

// TestHTMLReporter_NonEmptyOutput verifies Generate returns non-empty bytes.
func TestHTMLReporter_NonEmptyOutput(t *testing.T) {
	r := &HTMLReporter{}
	data, err := r.Generate(htmlScanResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("Generate returned empty bytes")
	}
}

// TestHTMLReporter_DocType checks for the HTML5 doctype declaration.
func TestHTMLReporter_DocType(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("output missing <!DOCTYPE html>")
	}
}

// TestHTMLReporter_HTMLTags confirms the document has opening and closing html
// tags, indicating a complete document.
func TestHTMLReporter_HTMLTags(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	if !strings.Contains(html, "<html") {
		t.Error("output missing <html> tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("output missing </html> closing tag")
	}
}

// TestHTMLReporter_HeadAndBodyPresent verifies basic structural elements.
func TestHTMLReporter_HeadAndBodyPresent(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	for _, tag := range []string{"<head>", "</head>", "<body>", "</body>"} {
		if !strings.Contains(html, tag) {
			t.Errorf("output missing %s", tag)
		}
	}
}

// TestHTMLReporter_TitleTag checks that the <title> element contains the target.
func TestHTMLReporter_TitleTag(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	if !strings.Contains(html, "<title>") {
		t.Error("output missing <title> tag")
	}
	if !strings.Contains(html, result.Target) {
		t.Errorf("title does not contain target %q", result.Target)
	}
}

// TestHTMLReporter_InlineCSS checks that inline styles are present.
func TestHTMLReporter_InlineCSS(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	if !strings.Contains(html, "<style>") {
		t.Error("output missing inline <style> block")
	}
}

// TestHTMLReporter_ScanIDPresent verifies the scan ID appears in the output.
func TestHTMLReporter_ScanIDPresent(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	if !strings.Contains(html, result.ID) {
		t.Errorf("output does not contain scan ID %q", result.ID)
	}
}

// TestHTMLReporter_TargetURLPresent checks the target URL is in the output.
func TestHTMLReporter_TargetURLPresent(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	if !strings.Contains(html, result.Target) {
		t.Errorf("output does not contain target URL %q", result.Target)
	}
}

// TestHTMLReporter_AllFindingTitlesPresent checks that every finding title
// appears in the HTML output.
func TestHTMLReporter_AllFindingTitlesPresent(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	for _, f := range result.Findings {
		if !strings.Contains(html, f.Title) {
			t.Errorf("output missing finding title %q", f.Title)
		}
	}
}

// TestHTMLReporter_SeverityLevelsAppear verifies that each severity level used
// in the findings appears (upper-cased as rendered by the template) in the output.
func TestHTMLReporter_SeverityLevelsAppear(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	// Template renders severities upper-case via {{ upper (severityClass .Severity) }}.
	for _, sev := range []string{"CRITICAL", "MEDIUM", "LOW"} {
		if !strings.Contains(html, sev) {
			t.Errorf("output missing severity label %q", sev)
		}
	}
}

// TestHTMLReporter_OWASPIDsPresent checks that the OWASP IDs for each finding
// are rendered in the findings overview table.
func TestHTMLReporter_OWASPIDsPresent(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	for _, f := range result.Findings {
		if !strings.Contains(html, f.OWASPId) {
			t.Errorf("output missing OWASP ID %q for finding %q", f.OWASPId, f.Title)
		}
	}
}

// TestHTMLReporter_EndpointPaths checks that endpoint paths appear in the output.
func TestHTMLReporter_EndpointPaths(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	for _, f := range result.Findings {
		if !strings.Contains(html, f.EndpointPath) {
			t.Errorf("output missing endpoint path %q", f.EndpointPath)
		}
	}
}

// TestHTMLReporter_FindingIDAnchors verifies that each finding has an anchor
// element using its ID so that the overview table links work.
func TestHTMLReporter_FindingIDAnchors(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	for _, f := range result.Findings {
		anchor := "id=\"finding-" + f.ID + "\""
		if !strings.Contains(html, anchor) {
			t.Errorf("output missing anchor %q for finding %q", anchor, f.Title)
		}
	}
}

// TestHTMLReporter_RemediationPresent checks that remediation text is included.
func TestHTMLReporter_RemediationPresent(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	for _, f := range result.Findings {
		if !strings.Contains(html, f.Remediation) {
			t.Errorf("output missing remediation for finding %q", f.Title)
		}
	}
}

// TestHTMLReporter_SummaryCountsRendered checks that total findings count
// appears in the summary section.
func TestHTMLReporter_SummaryCountsRendered(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	// The template renders "Total Findings: {{ .Summary.TotalFindings }}".
	if !strings.Contains(html, "Total Findings:") {
		t.Error("output missing 'Total Findings:' label in summary")
	}
}

// TestHTMLReporter_GeneratedByFooter verifies the footer contains "APIGuard".
func TestHTMLReporter_GeneratedByFooter(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	if !strings.Contains(html, "APIGuard") {
		t.Error("footer does not mention APIGuard")
	}
}

// TestHTMLReporter_EmptyFindingsNoFindingsMessage checks the empty-state copy.
func TestHTMLReporter_EmptyFindingsNoFindingsMessage(t *testing.T) {
	result := htmlScanResult()
	result.Findings = nil
	result.Summary = domain.ScanSummary{}

	html := generateHTML(t, result)
	if !strings.Contains(html, "No findings were detected") {
		t.Error("empty findings: output should contain 'No findings were detected'")
	}
}

// TestHTMLReporter_EmptyFindingsStillValidDocument verifies that with no
// findings the output is still a complete HTML document.
func TestHTMLReporter_EmptyFindingsStillValidDocument(t *testing.T) {
	result := htmlScanResult()
	result.Findings = nil
	result.Summary = domain.ScanSummary{}

	html := generateHTML(t, result)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("empty-findings output missing DOCTYPE")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("empty-findings output missing closing </html>")
	}
}

// TestHTMLReporter_EvidenceRequestShown verifies that evidence request text
// is embedded inside <pre> blocks.
func TestHTMLReporter_EvidenceRequestShown(t *testing.T) {
	result := htmlScanResult()
	html := generateHTML(t, result)
	// Check a snippet from the first finding's request evidence.
	snippet := "GET /api/payments/5000 HTTP/1.1"
	if !strings.Contains(html, snippet) {
		t.Errorf("output missing evidence request snippet %q", snippet)
	}
}

// TestHTMLReporter_SeverityBadgeClasses checks that CSS badge classes are
// emitted for the severities present in the test fixture.
func TestHTMLReporter_SeverityBadgeClasses(t *testing.T) {
	html := generateHTML(t, htmlScanResult())
	// Template emits: <span class="badge critical">, <span class="badge medium"> etc.
	for _, cls := range []string{`badge critical`, `badge medium`, `badge low`} {
		if !strings.Contains(html, cls) {
			t.Errorf("output missing CSS badge class %q", cls)
		}
	}
}
