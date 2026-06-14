package modules

import (
	"context"
	"testing"
)

// TestA8MissingSecurityHeadersFindings verifies that findings are produced when
// security headers are absent.
func TestA8MissingSecurityHeadersFindings(t *testing.T) {
	// Response has no security headers at all.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`),
		},
	}

	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a8-headers",
				Category: "misconfig_security_headers",
				Method:   "GET",
				Path:     "/api/resource",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for missing security headers, got none")
	}
}

// TestA8SecurityHeadersPresentNoFinding verifies that no X-Content-Type-Options or
// clickjacking findings are produced when required security headers are present.
func TestA8SecurityHeadersPresentNoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`,
				"X-Content-Type-Options", "nosniff",
				"X-Frame-Options", "DENY",
				"Strict-Transport-Security", "max-age=31536000",
			),
		},
	}

	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a8-headers-present",
				Category: "misconfig_security_headers",
				Method:   "GET",
				Path:     "/api/resource",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have no X-Content-Type-Options or clickjacking findings.
	for _, f := range findings {
		if f.Title == "Missing X-Content-Type-Options Header" {
			t.Error("unexpected X-Content-Type-Options finding when header is present")
		}
		if f.Title == "Missing Clickjacking Protection Header" {
			t.Error("unexpected clickjacking finding when X-Frame-Options is present")
		}
	}
}

// TestA8ServerVersionDisclosureFinding verifies that a finding is produced when the
// Server header includes a version number.
func TestA8ServerVersionDisclosureFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`,
				"X-Content-Type-Options", "nosniff",
				"X-Frame-Options", "DENY",
				"Server", "nginx/1.18.0",
			),
		},
	}

	mod := &MisconfigModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a8-server-version",
				Category: "misconfig_security_headers",
				Method:   "GET",
				Path:     "/api/resource",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Server Header Exposes Version Information" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a Server version disclosure finding, got none")
	}
}

// TestA8IDAndName verifies the module ID and name.
func TestA8IDAndName(t *testing.T) {
	mod := &MisconfigModule{}
	if mod.ID() != "a8_misconfiguration" {
		t.Errorf("expected ID a8_misconfiguration, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
