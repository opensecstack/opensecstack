package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// TestA6MassCreateFinding verifies that a MEDIUM finding is produced when a batch POST returns 200.
func TestA6MassCreateFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"created":100}`),
		},
	}

	mod := &SensitiveFlowModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a6-mass",
				Category: "sensitive_flow_mass_create",
				Method:   "POST",
				Path:     "/users",
				Body:     []byte(`{"name":"test"}`),
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}
	if findings[0].Severity != domain.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

// TestA6NoCaptchaFinding verifies that an INFO finding is produced when a sensitive flow
// endpoint returns 200 with no CAPTCHA headers.
func TestA6NoCaptchaFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`),
		},
	}

	mod := &SensitiveFlowModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a6-captcha",
				Category: "sensitive_flow_no_captcha_signal",
				Method:   "POST",
				Path:     "/register",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for missing captcha signal, got none")
	}
	if findings[0].Severity != domain.SeverityInfo {
		t.Errorf("expected INFO severity, got %s", findings[0].Severity)
	}
}

// TestA6IDAndName verifies the module ID and name.
func TestA6IDAndName(t *testing.T) {
	mod := &SensitiveFlowModule{}
	if mod.ID() != "a6_business_flow" {
		t.Errorf("expected ID a6_business_flow, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
