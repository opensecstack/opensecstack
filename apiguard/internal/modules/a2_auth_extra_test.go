package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// ---------------------------------------------------------------------------
// auth_token_expired
// ---------------------------------------------------------------------------

func TestAuthModule_ExpiredTokenAccepted_YieldsHighFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"data":"secret"}`),
		},
	}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_token_expired", Method: "GET", Path: "/users/{id}"},
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
	if findings[0].ModuleID != "a2_auth" {
		t.Errorf("expected module ID a2_auth, got %s", findings[0].ModuleID)
	}
}

func TestAuthModule_ExpiredTokenRejected_NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(401, `{"error":"token expired"}`),
		},
	}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_token_expired", Method: "GET", Path: "/users/{id}"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when expired token correctly rejected, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// auth_invalid_token
// ---------------------------------------------------------------------------

func TestAuthModule_InvalidTokenAccepted_YieldsCriticalFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"data":"secret"}`),
		},
	}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_invalid_token", Method: "GET", Path: "/users/{id}"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != domain.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestAuthModule_InvalidTokenRejected_NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(403, `{"error":"invalid token"}`),
		},
	}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_invalid_token", Method: "GET", Path: "/users/{id}"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// auth_token_replay
// ---------------------------------------------------------------------------

func TestAuthModule_TokenReplay_BothAccepted_YieldsLowFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`), // first request
			resp(200, `{"ok":true}`), // replayed second request
		},
	}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_token_replay", Method: "GET", Path: "/users/{id}"},
		},
	}
	auth := &AuthConfig{Type: "bearer", Token: "valid-token-abc"}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", auth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != domain.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
	if len(exec.calls) != 2 {
		t.Errorf("expected exactly 2 requests (initial + replay), got %d", len(exec.calls))
	}
}

func TestAuthModule_TokenReplay_SecondRejected_NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`),
			resp(401, `{"error":"replay detected"}`),
		},
	}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_token_replay", Method: "GET", Path: "/users/{id}"},
		},
	}
	auth := &AuthConfig{Type: "bearer", Token: "valid-token-abc"}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", auth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when replay is rejected, got %d", len(findings))
	}
}

func TestAuthModule_TokenReplay_NilAuthSkipsCheck(t *testing.T) {
	// No token provided — nothing to replay, module must not fabricate a finding
	// or issue any requests.
	exec := &mockExecutor{}
	mod := &AuthModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{ID: "tc1", Category: "auth_token_replay", Method: "GET", Path: "/users/{id}"},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings with nil auth, got %d", len(findings))
	}
	if len(exec.calls) != 0 {
		t.Errorf("expected no HTTP calls with nil auth, got %d", len(exec.calls))
	}
}
