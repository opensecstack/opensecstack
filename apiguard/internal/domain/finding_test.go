package domain

import "testing"

// TestSeverityExactStringValues verifies the precise string representations
// of each Severity constant, which are embedded in JSON output and compared
// by external consumers.
func TestSeverityExactStringValues(t *testing.T) {
	cases := []struct {
		constant Severity
		want     string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tc := range cases {
		if string(tc.constant) != tc.want {
			t.Errorf("Severity constant = %q, want %q", tc.constant, tc.want)
		}
	}
}

// TestSeverityDistinct ensures that no two Severity constants share the same
// underlying value.
func TestSeverityDistinct(t *testing.T) {
	seen := make(map[Severity]bool)
	for _, s := range []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
	} {
		if seen[s] {
			t.Errorf("duplicate Severity value: %q", s)
		}
		seen[s] = true
	}
}

// TestFindingStatusExactStringValues verifies the precise string representation
// of every FindingStatus constant used in JSON serialisation and database storage.
func TestFindingStatusExactStringValues(t *testing.T) {
	cases := []struct {
		constant FindingStatus
		want     string
	}{
		{FindingStatusOpen, "open"},
		{FindingStatusConfirmed, "confirmed"},
		{FindingStatusFalsePositive, "false_positive"},
		{FindingStatusAccepted, "accepted"},
		{FindingStatusFixed, "fixed"},
	}
	for _, tc := range cases {
		if string(tc.constant) != tc.want {
			t.Errorf("FindingStatus constant = %q, want %q", tc.constant, tc.want)
		}
	}
}

// TestFindingStatusDistinct ensures no two FindingStatus constants share a value.
func TestFindingStatusDistinct(t *testing.T) {
	seen := make(map[FindingStatus]bool)
	for _, s := range []FindingStatus{
		FindingStatusOpen,
		FindingStatusConfirmed,
		FindingStatusFalsePositive,
		FindingStatusAccepted,
		FindingStatusFixed,
	} {
		if seen[s] {
			t.Errorf("duplicate FindingStatus value: %q", s)
		}
		seen[s] = true
	}
}

// TestFindingStructFields verifies that a Finding can be constructed with all
// fields set and that each field holds the assigned value.
func TestFindingStructFields(t *testing.T) {
	ev := Evidence{
		Request:  "GET /test HTTP/1.1",
		Response: "HTTP/1.1 200 OK",
		Detail:   map[string]interface{}{"key": "value"},
	}

	f := Finding{
		ID:             "f-123",
		ScanID:         "scan-456",
		OWASPId:        "API3:2023",
		ModuleID:       "a3_mass_assignment",
		Title:          "Mass Assignment Vulnerability",
		Description:    "Attacker sets privileged fields.",
		Severity:       SeverityHigh,
		CVSSScore:      8.0,
		CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		EndpointPath:   "/v1/users/{id}",
		EndpointMethod: "PATCH",
		Evidence:       ev,
		Remediation:    "Use allowlist for writable fields.",
		Status:         FindingStatusConfirmed,
	}

	if f.ID != "f-123" {
		t.Errorf("ID = %q, want f-123", f.ID)
	}
	if f.ScanID != "scan-456" {
		t.Errorf("ScanID = %q, want scan-456", f.ScanID)
	}
	if f.OWASPId != "API3:2023" {
		t.Errorf("OWASPId = %q, want API3:2023", f.OWASPId)
	}
	if f.ModuleID != "a3_mass_assignment" {
		t.Errorf("ModuleID = %q, want a3_mass_assignment", f.ModuleID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CVSSScore != 8.0 {
		t.Errorf("CVSSScore = %f, want 8.0", f.CVSSScore)
	}
	if f.EndpointPath != "/v1/users/{id}" {
		t.Errorf("EndpointPath = %q, want /v1/users/{id}", f.EndpointPath)
	}
	if f.EndpointMethod != "PATCH" {
		t.Errorf("EndpointMethod = %q, want PATCH", f.EndpointMethod)
	}
	if f.Evidence.Request != ev.Request {
		t.Errorf("Evidence.Request = %q, want %q", f.Evidence.Request, ev.Request)
	}
	if f.Evidence.Response != ev.Response {
		t.Errorf("Evidence.Response = %q, want %q", f.Evidence.Response, ev.Response)
	}
	if f.Status != FindingStatusConfirmed {
		t.Errorf("Status = %q, want confirmed", f.Status)
	}
}

// TestFindingZeroValue checks that the zero value of Finding does not panic
// and has zero/empty/false values for all fields.
func TestFindingZeroValue(t *testing.T) {
	var f Finding

	if f.ID != "" {
		t.Errorf("zero Finding.ID should be empty, got %q", f.ID)
	}
	if f.Severity != "" {
		t.Errorf("zero Finding.Severity should be empty, got %q", f.Severity)
	}
	if f.CVSSScore != 0 {
		t.Errorf("zero Finding.CVSSScore should be 0, got %f", f.CVSSScore)
	}
	if f.Status != "" {
		t.Errorf("zero Finding.Status should be empty, got %q", f.Status)
	}
}

// TestEvidenceDetailMap verifies that the Detail field on Evidence accepts
// arbitrary key-value pairs and retrieves them correctly.
func TestEvidenceDetailMap(t *testing.T) {
	ev := Evidence{
		Detail: map[string]interface{}{
			"status_code": 200,
			"headers":     []string{"Content-Type: application/json"},
		},
	}

	if ev.Detail["status_code"] != 200 {
		t.Errorf("Evidence.Detail[status_code] = %v, want 200", ev.Detail["status_code"])
	}
	if ev.Detail["headers"] == nil {
		t.Error("Evidence.Detail[headers] should not be nil")
	}
}

// TestEvidenceZeroValue checks that an Evidence struct can be used without
// initialising the Detail map.
func TestEvidenceZeroValue(t *testing.T) {
	var ev Evidence
	if ev.Request != "" {
		t.Errorf("zero Evidence.Request should be empty")
	}
	if ev.Response != "" {
		t.Errorf("zero Evidence.Response should be empty")
	}
	if ev.Detail != nil {
		t.Errorf("zero Evidence.Detail should be nil")
	}
}
