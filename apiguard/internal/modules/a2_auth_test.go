package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// TestAuthRemovalFinding verifies that a CRITICAL finding (with CVSSScore > 0) is produced
// when the endpoint returns 200 without any authentication.
func TestAuthRemovalFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"data":"secret"}`),
		},
	}

	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "auth_removal",
				Method:   "GET",
				Path:     "/users/{id}",
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
	f := findings[0]
	if f.Severity != domain.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.CVSSScore <= 0 {
		t.Errorf("expected CVSSScore > 0, got %f", f.CVSSScore)
	}
}

// TestAuthRemovalNoFinding verifies that no finding is produced when the endpoint returns 401.
func TestAuthRemovalNoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(401, `{"error":"unauthorized"}`),
		},
	}

	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc2",
				Category: "auth_removal",
				Method:   "GET",
				Path:     "/users/{id}",
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

// TestAuthUnprotectedWrite verifies that a MEDIUM finding is produced when a POST endpoint
// returns 200 without authentication.
func TestAuthUnprotectedWrite(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"created":true}`),
		},
	}

	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc3",
				Category: "auth_unprotected_write",
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

// TestAuthIDAndName verifies the module ID and Name.
func TestAuthIDAndName(t *testing.T) {
	mod := &AuthModule{}
	if mod.ID() != "a2_auth" {
		t.Errorf("expected ID a2_auth, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
