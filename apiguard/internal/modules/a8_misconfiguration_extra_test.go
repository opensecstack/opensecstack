package modules

import (
	"context"
	"regexp"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// ---------------------------------------------------------------------------
// extractSnippet
// ---------------------------------------------------------------------------

func TestExtractSnippet_ReturnsWindowAroundMatch(t *testing.T) {
	pat := regexp.MustCompile(`Traceback`)
	body := []byte("prefix padding text here Traceback (most recent call last) more content after")
	snippet := extractSnippet(body, pat)
	if snippet == "" {
		t.Fatal("expected a non-empty snippet")
	}
	if !regexp.MustCompile(`Traceback`).MatchString(snippet) {
		t.Errorf("expected snippet to contain the match, got %q", snippet)
	}
}

func TestExtractSnippet_NoMatchReturnsEmpty(t *testing.T) {
	pat := regexp.MustCompile(`Traceback`)
	body := []byte("nothing interesting here")
	snippet := extractSnippet(body, pat)
	if snippet != "" {
		t.Errorf("expected empty snippet for no match, got %q", snippet)
	}
}

func TestExtractSnippet_ClampsAtBodyBoundaries(t *testing.T) {
	pat := regexp.MustCompile(`^Exception`)
	body := []byte("Exception")
	snippet := extractSnippet(body, pat)
	if snippet != "Exception" {
		t.Errorf("expected snippet to be exactly 'Exception' when match is at start/end of short body, got %q", snippet)
	}
}

// ---------------------------------------------------------------------------
// MisconfigModule.Run — misconfig_debug_info
// ---------------------------------------------------------------------------

func TestMisconfig_DebugInfoLeak_YieldsHighFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(500, `{"error":"Traceback (most recent call last): File \"app.py\", line 10"}`),
		},
	}
	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "misconfig_debug_info", Method: "GET", Path: "/users/1"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != domain.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if findings[0].OWASPId != "API8:2023" {
		t.Errorf("expected OWASPId API8:2023, got %s", findings[0].OWASPId)
	}
}

func TestMisconfig_NoDebugInfo_NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"data":"clean response"}`),
		},
	}
	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "misconfig_debug_info", Method: "GET", Path: "/users/1"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for clean response, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// MisconfigModule.Run — misconfig_http_methods
// ---------------------------------------------------------------------------

func TestMisconfig_DangerousMethodTraceAllowed_YieldsMediumFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, "", "Allow", "GET, POST, TRACE"),
		},
	}
	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "misconfig_http_methods", Method: "OPTIONS", Path: "/users/1"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != domain.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestMisconfig_OnlySafeMethodsAllowed_NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, "", "Allow", "GET, POST, PUT, DELETE"),
		},
	}
	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "misconfig_http_methods", Method: "OPTIONS", Path: "/users/1"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when only safe methods are allowed, got %d", len(findings))
	}
}

func TestMisconfig_BothTraceAndConnectAllowed_YieldsTwoFindings(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, "", "Allow", "GET, TRACE, CONNECT"),
		},
	}
	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "misconfig_http_methods", Method: "OPTIONS", Path: "/users/1"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (TRACE + CONNECT), got %d", len(findings))
	}
}
