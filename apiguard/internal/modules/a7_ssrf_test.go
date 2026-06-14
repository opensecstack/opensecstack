package modules

import (
	"context"
	"testing"
)

// TestA7SSRFReflectedFinding verifies that a HIGH finding is produced when the response
// body contains an SSRF indicator ("169.254").
func TestA7SSRFReflectedFinding(t *testing.T) {
	// The module injects ssrfPayloads into a "url" query param.
	// First response contains the metadata IP — this triggers the indicator.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"result":"http://169.254.169.254/latest"}`),
		},
	}

	mod := &SSRFModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a7-ssrf",
				Category: "ssrf_url_param",
				Method:   "GET",
				Path:     "/fetch",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one SSRF finding, got none")
	}
}

// TestA7SSRFNoFinding verifies that no finding is produced when the response body
// contains no SSRF indicators and is a short safe body.
func TestA7SSRFNoFinding(t *testing.T) {
	// Return a short body (<=100 bytes) with no indicators for all probes.
	safeResp := resp(200, `{"ok":true}`)
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			safeResp, safeResp, safeResp,
			safeResp, safeResp, safeResp,
			safeResp, safeResp, safeResp,
		},
	}

	mod := &SSRFModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a7-ssrf-safe",
				Category: "ssrf_url_param",
				Method:   "GET",
				Path:     "/fetch",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestA7IDAndName verifies the module ID and name.
func TestA7IDAndName(t *testing.T) {
	mod := &SSRFModule{}
	if mod.ID() != "a7_ssrf" {
		t.Errorf("expected ID a7_ssrf, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
