package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// ---------------------------------------------------------------------------
// extractReadOnlyFieldsFromBody
// ---------------------------------------------------------------------------

func TestExtractReadOnlyFieldsFromBody_PicksKnownFields(t *testing.T) {
	body := []byte(`{"id":42,"role":"admin","name":"alice","created_at":"2021-01-01T00:00:00Z"}`)
	got := extractReadOnlyFieldsFromBody(body)

	if v, ok := got["id"]; !ok || v != float64(42) {
		t.Errorf("expected id=42, got %v (present=%v)", v, ok)
	}
	if v, ok := got["role"]; !ok || v != "admin" {
		t.Errorf("expected role=admin, got %v (present=%v)", v, ok)
	}
	if _, ok := got["name"]; ok {
		t.Error("expected 'name' to be excluded (not a known read-only field)")
	}
	if _, ok := got["created_at"]; !ok {
		t.Error("expected created_at to be present")
	}
}

func TestExtractReadOnlyFieldsFromBody_InvalidJSONFallsBackToDefaults(t *testing.T) {
	got := extractReadOnlyFieldsFromBody([]byte(`not json`))
	if _, ok := got["id"]; !ok {
		t.Error("expected fallback default 'id' field")
	}
	if _, ok := got["created_at"]; !ok {
		t.Error("expected fallback default 'created_at' field")
	}
	if len(got) != 3 {
		t.Errorf("expected exactly 3 fallback fields, got %d", len(got))
	}
}

func TestExtractReadOnlyFieldsFromBody_NoKnownFieldsFallsBackToDefaults(t *testing.T) {
	got := extractReadOnlyFieldsFromBody([]byte(`{"name":"alice","email":"a@example.com"}`))
	if _, ok := got["id"]; !ok {
		t.Error("expected fallback default 'id' field when body has no known read-only fields")
	}
}

// ---------------------------------------------------------------------------
// MassAssignmentModule.Run — mass_assign_readonly
// ---------------------------------------------------------------------------

func TestMassAssignment_ReadOnlyFieldReflected_YieldsHighFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"id":99999,"name":"alice"}`),
		},
	}
	mod := &MassAssignmentModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "mass_assign_readonly",
				Method:   "PATCH",
				Path:     "/users/1",
				Body:     []byte(`{"id":99999,"name":"alice"}`),
			},
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
	if findings[0].OWASPId != "API3:2023" {
		t.Errorf("expected OWASPId API3:2023, got %s", findings[0].OWASPId)
	}
}

func TestMassAssignment_ReadOnlyFieldRejectedWith422_NoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(422, `{"error":"validation failed"}`),
		},
	}
	mod := &MassAssignmentModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "mass_assign_readonly",
				Method:   "PATCH",
				Path:     "/users/1",
				Body:     []byte(`{"id":99999}`),
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on 422 rejection, got %d", len(findings))
	}
}

func TestMassAssignment_ReadOnlyFieldNotReflected_NoFinding(t *testing.T) {
	// Attack succeeds (2xx) but the response does not echo back the injected
	// read-only field value — the server silently ignored it, which is fine.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"id":1,"name":"alice"}`),
		},
	}
	mod := &MassAssignmentModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "mass_assign_readonly",
				Method:   "PATCH",
				Path:     "/users/1",
				Body:     []byte(`{"id":99999}`),
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when injected value is not reflected, got %d", len(findings))
	}
}
