package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// TestFunctionAuthAdminEndpointFinding verifies that a CRITICAL finding is produced
// when an admin endpoint returns 200 without any authentication.
func TestFunctionAuthAdminEndpointFinding(t *testing.T) {
	// runAdminEndpoint sends 1 unauthenticated request.
	// auth is nil so only the unauthenticated check runs.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"users":[]}`), // no-auth request → 200 → CRITICAL
		},
	}

	mod := &FunctionAuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "function_auth_admin_endpoint",
				Method:   "GET",
				Path:     "/admin/users",
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
	if findings[0].Severity != domain.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

// TestFunctionAuthAdminEndpointNoFinding verifies that no finding is produced when the
// admin endpoint returns 403 (properly protected).
func TestFunctionAuthAdminEndpointNoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(403, `{"error":"forbidden"}`),
		},
	}

	mod := &FunctionAuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc2",
				Category: "function_auth_admin_endpoint",
				Method:   "GET",
				Path:     "/admin/users",
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

// TestFunctionAuthMethodSwapFinding verifies that a finding is produced when swapping the
// HTTP method (e.g., GET → POST) on an endpoint returns 200 without authentication.
func TestFunctionAuthMethodSwapFinding(t *testing.T) {
	// runMethodSwap for GET tries POST, PUT, DELETE with NO auth.
	// First alternative method (POST) returns 200 → finding.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"deleted":true}`), // POST attempt → 200
		},
	}

	mod := &FunctionAuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc3",
				Category: "function_auth_http_method_swap",
				Method:   "GET",
				Path:     "/users",
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
}

// TestFunctionAuthIDAndName verifies the module ID and Name.
func TestFunctionAuthIDAndName(t *testing.T) {
	mod := &FunctionAuthModule{}
	if mod.ID() != "a5_function_auth" {
		t.Errorf("expected ID a5_function_auth, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
