package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// TestBOLAIDEnumFinding verifies that a CRITICAL finding is produced when a probe ID
// returns HTTP 200, indicating missing object-level authorization.
func TestBOLAIDEnumFinding(t *testing.T) {
	// Path must contain a {param} template so generateTestIDs returns IDs.
	// Baseline uses ID "1", then probes "2","3",... — second call uses "2".
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"id":1}`),           // baseline (ID=1)
			resp(200, `{"id":2,"secret":"x"}`), // probe (ID=2) → BOLA finding
		},
	}

	mod := &BOLAModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "bola_id_enum",
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
	if findings[0].Severity != domain.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

// TestBOLAIDEnumNoFinding verifies that no finding is produced when all probes return 404.
func TestBOLAIDEnumNoFinding(t *testing.T) {
	// All responses are 404 — baseline is 404, which means both baseline and probes fail.
	// Actually baseline 404 does not short-circuit (only 401/403 do), so we need
	// baseline to return 200 and all probes to return 404.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"id":1}`), // baseline
			// all subsequent probes return 404 (mock returns 404 for out-of-range idx)
		},
	}

	mod := &BOLAModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc2",
				Category: "bola_id_enum",
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

// TestBOLACrossUserFinding verifies that accessing another user's resource with an alternate
// token produces a CRITICAL finding.
func TestBOLACrossUserFinding(t *testing.T) {
	// Cross-user: uses the first testID ("1") with the other token.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"id":1,"data":"secret"}`), // cross-user probe with other token → 200
		},
	}

	mod := &BOLAModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc3",
				Category: "bola_cross_user",
				Method:   "GET",
				Path:     "/users/{id}",
			},
		},
	}
	auth := &AuthConfig{
		Type:        "bearer",
		Token:       "user-a-token",
		OtherTokens: []string{"other-token"},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", auth)
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

// TestBOLARegistry verifies that the module registry contains the a1_bola module.
func TestBOLARegistry(t *testing.T) {
	reg := NewRegistry()
	mod, ok := reg.Get("a1_bola")
	if !ok {
		t.Fatal("a1_bola not found in registry")
	}
	if mod.ID() != "a1_bola" {
		t.Errorf("expected ID a1_bola, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
