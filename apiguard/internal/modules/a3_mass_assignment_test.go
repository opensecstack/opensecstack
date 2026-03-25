package modules

import (
	"context"
	"testing"
)

// TestMassAssignExtraFieldsFinding verifies that a finding is produced when the server
// reflects injected extra fields (admin/role/is_admin) back in the response.
func TestMassAssignExtraFieldsFinding(t *testing.T) {
	// The module: (1) sends baseline body, (2) sends body with admin/role/is_admin injected.
	// A finding is raised when those injected fields appear in the attack response.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			// baseline response
			resp(200, `{"name":"test"}`),
			// attack response — reflects injected fields
			resp(200, `{"name":"test","admin":true,"role":"admin","is_admin":true}`),
		},
	}

	mod := &MassAssignmentModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "mass_assign_extra_fields",
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
}

// TestMassAssignNoFinding verifies that no finding is produced when the attack response is
// identical to the baseline and contains no reflected injected fields.
func TestMassAssignNoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			// baseline response
			resp(200, `{"name":"test"}`),
			// attack response identical — no extra fields reflected
			resp(200, `{"name":"test"}`),
		},
	}

	mod := &MassAssignmentModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc2",
				Category: "mass_assign_extra_fields",
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
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestMassAssignIDAndName verifies the module ID and Name.
func TestMassAssignIDAndName(t *testing.T) {
	mod := &MassAssignmentModule{}
	if mod.ID() != "a3_mass_assignment" {
		t.Errorf("expected ID a3_mass_assignment, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
