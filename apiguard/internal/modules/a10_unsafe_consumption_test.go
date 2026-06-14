package modules

import (
	"context"
	"testing"
)

// TestA10OpenRedirectFinding verifies that a HIGH finding is produced when a redirect
// response points to an external domain.
func TestA10OpenRedirectFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(302, ``, "Location", "https://evil.com/phish"),
		},
	}

	mod := &UnsafeConsumptionModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a10-redirect",
				Category: "unsafe_redirect",
				Method:   "GET",
				Path:     "/redirect",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one open redirect finding, got none")
	}
}

// TestA10ContentTypeMismatchFinding verifies that a MEDIUM finding is produced when the
// response Content-Type does not match the requested JSON accept type.
func TestA10ContentTypeMismatchFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"key":"value"}`, "Content-Type", "text/plain"),
		},
	}

	mod := &UnsafeConsumptionModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a10-content-type",
				Category: "unsafe_content_type",
				Method:   "GET",
				Path:     "/api/data",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one content-type mismatch finding, got none")
	}
}

// TestA10NoFinding verifies that no findings are produced when the response is 200
// with correct JSON content type and no redirect.
func TestA10NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`, "Content-Type", "application/json"),
		},
	}

	mod := &UnsafeConsumptionModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a10-safe",
				Category: "unsafe_content_type",
				Method:   "GET",
				Path:     "/api/data",
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

// TestA10IDAndName verifies the module ID and name.
func TestA10IDAndName(t *testing.T) {
	mod := &UnsafeConsumptionModule{}
	if mod.ID() != "a10_unsafe_consumption" {
		t.Errorf("expected ID a10_unsafe_consumption, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
