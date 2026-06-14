package opensecstack

import (
	"encoding/json"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// ScanStatus constants
// ----------------------------------------------------------------------------

func TestScanStatus_StringValues(t *testing.T) {
	tests := []struct {
		name string
		got  ScanStatus
		want string
	}{
		{"Pending", ScanStatusPending, "pending"},
		{"Running", ScanStatusRunning, "running"},
		{"Completed", ScanStatusCompleted, "completed"},
		{"Failed", ScanStatusFailed, "failed"},
		{"Cancelled", ScanStatusCancelled, "cancelled"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.got) != tc.want {
				t.Errorf("ScanStatus%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestScanStatus_Distinct(t *testing.T) {
	statuses := []ScanStatus{
		ScanStatusPending,
		ScanStatusRunning,
		ScanStatusCompleted,
		ScanStatusFailed,
		ScanStatusCancelled,
	}
	seen := make(map[ScanStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate ScanStatus value: %q", s)
		}
		seen[s] = true
	}
}

// ----------------------------------------------------------------------------
// FindingSeverity constants
// ----------------------------------------------------------------------------

func TestFindingSeverity_StringValues(t *testing.T) {
	tests := []struct {
		name string
		got  FindingSeverity
		want string
	}{
		{"Critical", FindingSeverityCritical, "critical"},
		{"High", FindingSeverityHigh, "high"},
		{"Medium", FindingSeverityMedium, "medium"},
		{"Low", FindingSeverityLow, "low"},
		{"Info", FindingSeverityInfo, "info"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.got) != tc.want {
				t.Errorf("FindingSeverity%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestFindingSeverity_Distinct(t *testing.T) {
	severities := []FindingSeverity{
		FindingSeverityCritical,
		FindingSeverityHigh,
		FindingSeverityMedium,
		FindingSeverityLow,
		FindingSeverityInfo,
	}
	seen := make(map[FindingSeverity]bool)
	for _, s := range severities {
		if seen[s] {
			t.Errorf("duplicate FindingSeverity value: %q", s)
		}
		seen[s] = true
	}
}

// ----------------------------------------------------------------------------
// FindingStatus constants
// ----------------------------------------------------------------------------

func TestFindingStatus_StringValues(t *testing.T) {
	tests := []struct {
		name string
		got  FindingStatus
		want string
	}{
		{"Open", FindingStatusOpen, "open"},
		{"Confirmed", FindingStatusConfirmed, "confirmed"},
		{"FalsePositive", FindingStatusFalsePositive, "false_positive"},
		{"Accepted", FindingStatusAccepted, "accepted"},
		{"Fixed", FindingStatusFixed, "fixed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.got) != tc.want {
				t.Errorf("FindingStatus%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestFindingStatus_Distinct(t *testing.T) {
	statuses := []FindingStatus{
		FindingStatusOpen,
		FindingStatusConfirmed,
		FindingStatusFalsePositive,
		FindingStatusAccepted,
		FindingStatusFixed,
	}
	seen := make(map[FindingStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate FindingStatus value: %q", s)
		}
		seen[s] = true
	}
}

// ----------------------------------------------------------------------------
// Scan — JSON round-trip
// ----------------------------------------------------------------------------

func TestScan_JSONRoundTrip(t *testing.T) {
	now := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	started := time.Date(2024, 1, 15, 10, 1, 0, 0, time.UTC)

	original := Scan{
		ID:            "scan-abc-123",
		SpecURL:       "https://api.example.com/openapi.json",
		SpecHash:      "sha256:deadbeef",
		TargetURL:     "https://api.example.com",
		Status:        ScanStatusCompleted,
		Modules:       []string{"bola", "broken_auth"},
		TotalFindings: 5,
		CriticalCount: 1,
		HighCount:     2,
		MediumCount:   1,
		LowCount:      1,
		InfoCount:     0,
		ErrorMessage:  "",
		StartedAt:     &started,
		CompletedAt:   nil,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal(Scan): %v", err)
	}

	var decoded Scan
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(Scan): %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.SpecURL != original.SpecURL {
		t.Errorf("SpecURL: got %q, want %q", decoded.SpecURL, original.SpecURL)
	}
	if decoded.TargetURL != original.TargetURL {
		t.Errorf("TargetURL: got %q, want %q", decoded.TargetURL, original.TargetURL)
	}
	if decoded.Status != ScanStatusCompleted {
		t.Errorf("Status: got %q, want %q", decoded.Status, ScanStatusCompleted)
	}
	if decoded.TotalFindings != original.TotalFindings {
		t.Errorf("TotalFindings: got %d, want %d", decoded.TotalFindings, original.TotalFindings)
	}
	if decoded.CriticalCount != 1 {
		t.Errorf("CriticalCount: got %d, want 1", decoded.CriticalCount)
	}
	if len(decoded.Modules) != 2 || decoded.Modules[0] != "bola" {
		t.Errorf("Modules: got %v", decoded.Modules)
	}
	if decoded.StartedAt == nil {
		t.Error("StartedAt: got nil, want non-nil")
	} else if !decoded.StartedAt.Equal(started) {
		t.Errorf("StartedAt: got %v, want %v", decoded.StartedAt, started)
	}
	if decoded.CompletedAt != nil {
		t.Errorf("CompletedAt: got %v, want nil", decoded.CompletedAt)
	}
}

func TestScan_JSONTagNames(t *testing.T) {
	s := Scan{
		ID:        "tag-test",
		Status:    ScanStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	expectedKeys := []string{
		"id", "spec_url", "spec_hash", "target_url", "status",
		"modules", "total_findings", "critical_count", "high_count",
		"medium_count", "low_count", "info_count", "error_message",
		"created_at", "updated_at",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found in marshalled Scan", key)
		}
	}
}

// ----------------------------------------------------------------------------
// Finding — JSON round-trip
// ----------------------------------------------------------------------------

func TestFinding_JSONRoundTrip(t *testing.T) {
	now := time.Date(2024, 1, 15, 10, 5, 0, 0, time.UTC)
	triaged := time.Date(2024, 1, 16, 9, 0, 0, 0, time.UTC)

	original := Finding{
		ID:             "finding-xyz",
		ScanID:         "scan-abc-123",
		OwaspID:        "API1:2023",
		ModuleID:       "bola",
		Title:          "Broken Object Level Authorization",
		Description:    "An attacker can access resources of other users.",
		Severity:       FindingSeverityCritical,
		CVSSScore:      9.1,
		CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		EndpointPath:   "/api/v1/users/{id}",
		EndpointMethod: "GET",
		Remediation:    "Implement access control checks.",
		Status:         FindingStatusOpen,
		TriagedBy:      "",
		TriageNote:     "",
		TriagedAt:      &triaged,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal(Finding): %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(Finding): %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.ScanID != original.ScanID {
		t.Errorf("ScanID: got %q, want %q", decoded.ScanID, original.ScanID)
	}
	if decoded.Severity != FindingSeverityCritical {
		t.Errorf("Severity: got %q, want %q", decoded.Severity, FindingSeverityCritical)
	}
	if decoded.Status != FindingStatusOpen {
		t.Errorf("Status: got %q, want %q", decoded.Status, FindingStatusOpen)
	}
	if decoded.CVSSScore != 9.1 {
		t.Errorf("CVSSScore: got %v, want 9.1", decoded.CVSSScore)
	}
	if decoded.OwaspID != "API1:2023" {
		t.Errorf("OwaspID: got %q, want %q", decoded.OwaspID, "API1:2023")
	}
	if decoded.TriagedAt == nil {
		t.Error("TriagedAt: got nil, want non-nil")
	} else if !decoded.TriagedAt.Equal(triaged) {
		t.Errorf("TriagedAt: got %v, want %v", decoded.TriagedAt, triaged)
	}
}

func TestFinding_JSONTagNames(t *testing.T) {
	f := Finding{
		ID:        "tag-test",
		Severity:  FindingSeverityHigh,
		Status:    FindingStatusOpen,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	expectedKeys := []string{
		"id", "scan_id", "owasp_id", "module_id", "title", "description",
		"severity", "cvss_score", "cvss_vector", "endpoint_path",
		"endpoint_method", "remediation", "status", "triaged_by",
		"triage_note", "created_at", "updated_at",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found in marshalled Finding", key)
		}
	}
}

func TestFinding_NilTriagedAt(t *testing.T) {
	const jsonStr = `{
		"id": "f1",
		"scan_id": "s1",
		"owasp_id": "",
		"module_id": "",
		"title": "",
		"description": "",
		"severity": "info",
		"cvss_score": 0,
		"cvss_vector": "",
		"endpoint_path": "",
		"endpoint_method": "",
		"remediation": "",
		"status": "open",
		"triaged_by": "",
		"triage_note": "",
		"triaged_at": null,
		"created_at": "2024-01-15T10:00:00Z",
		"updated_at": "2024-01-15T10:00:00Z"
	}`
	var f Finding
	if err := json.Unmarshal([]byte(jsonStr), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.TriagedAt != nil {
		t.Errorf("TriagedAt: expected nil for JSON null, got %v", f.TriagedAt)
	}
}

// ----------------------------------------------------------------------------
// Scan — zero values
// ----------------------------------------------------------------------------

func TestScan_ZeroValues(t *testing.T) {
	var s Scan
	if s.ID != "" {
		t.Errorf("zero ID should be empty string, got %q", s.ID)
	}
	if s.Status != "" {
		t.Errorf("zero Status should be empty string, got %q", s.Status)
	}
	if s.TotalFindings != 0 {
		t.Errorf("zero TotalFindings should be 0, got %d", s.TotalFindings)
	}
	if s.Modules != nil {
		t.Errorf("zero Modules should be nil, got %v", s.Modules)
	}
	if s.StartedAt != nil {
		t.Errorf("zero StartedAt should be nil, got %v", s.StartedAt)
	}
	if s.CompletedAt != nil {
		t.Errorf("zero CompletedAt should be nil, got %v", s.CompletedAt)
	}
}

// ----------------------------------------------------------------------------
// Finding — zero values
// ----------------------------------------------------------------------------

func TestFinding_ZeroValues(t *testing.T) {
	var f Finding
	if f.ID != "" {
		t.Errorf("zero ID should be empty string, got %q", f.ID)
	}
	if f.Severity != "" {
		t.Errorf("zero Severity should be empty string, got %q", f.Severity)
	}
	if f.Status != "" {
		t.Errorf("zero Status should be empty string, got %q", f.Status)
	}
	if f.CVSSScore != 0 {
		t.Errorf("zero CVSSScore should be 0, got %v", f.CVSSScore)
	}
	if f.TriagedAt != nil {
		t.Errorf("zero TriagedAt should be nil, got %v", f.TriagedAt)
	}
}

// ----------------------------------------------------------------------------
// RateLimitError
// ----------------------------------------------------------------------------

func TestRateLimitError_ErrorMethod(t *testing.T) {
	msg := "rate limited: too many requests"
	rle := &RateLimitError{Message: msg, RetryAfter: 30}
	if rle.Error() != msg {
		t.Errorf("Error(): got %q, want %q", rle.Error(), msg)
	}
	if rle.RetryAfter != 30 {
		t.Errorf("RetryAfter: got %d, want 30", rle.RetryAfter)
	}
}

func TestRateLimitError_ZeroRetryAfter(t *testing.T) {
	rle := &RateLimitError{Message: "rate limited"}
	if rle.RetryAfter != 0 {
		t.Errorf("default RetryAfter should be 0, got %d", rle.RetryAfter)
	}
}

// ----------------------------------------------------------------------------
// Organisation — JSON round-trip
// ----------------------------------------------------------------------------

func TestOrganisation_JSONRoundTrip(t *testing.T) {
	now := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	original := Organisation{
		ID:                 "org-001",
		Name:               "Acme Corp",
		Industry:           "technology",
		Country:            "DE",
		Size:               "large",
		EntityType:         "essential",
		RegistrationNumber: "DE123456",
		ContactEmail:       "security@acme.example",
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal(Organisation): %v", err)
	}

	var decoded Organisation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(Organisation): %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Name != original.Name {
		t.Errorf("Name: got %q, want %q", decoded.Name, original.Name)
	}
	if decoded.Country != original.Country {
		t.Errorf("Country: got %q, want %q", decoded.Country, original.Country)
	}
	if decoded.RegistrationNumber != original.RegistrationNumber {
		t.Errorf("RegistrationNumber: got %q, want %q", decoded.RegistrationNumber, original.RegistrationNumber)
	}
}

// omitempty fields should be absent from JSON when empty.
func TestOrganisation_OmitEmpty(t *testing.T) {
	org := Organisation{
		ID:        "org-002",
		Name:      "Minimal Corp",
		Industry:  "finance",
		Country:   "FR",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	data, err := json.Marshal(org)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// These fields use omitempty so they should be absent when empty.
	for _, absent := range []string{"registration_number", "contact_email"} {
		if _, ok := raw[absent]; ok {
			t.Errorf("expected key %q to be omitted when empty, but it is present", absent)
		}
	}

	// These fields are always present.
	for _, present := range []string{"id", "name", "industry", "country"} {
		if _, ok := raw[present]; !ok {
			t.Errorf("expected key %q to be present, but it is absent", present)
		}
	}
}

// ----------------------------------------------------------------------------
// Assessment — JSON round-trip including optional Stats
// ----------------------------------------------------------------------------

func TestAssessment_JSONRoundTrip(t *testing.T) {
	now := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	avg := 7.5
	original := Assessment{
		ID:               "asmt-001",
		OrgID:            "org-001",
		Title:            "Annual NIS2 Assessment",
		Status:           "in_progress",
		FrameworkVersion: "2.0",
		Scope:            "All EU operations",
		Assessor:         "Jane Smith",
		DueDate:          "2024-12-31",
		CompletedAt:      nil,
		CreatedAt:        now,
		UpdatedAt:        now,
		Stats: &AssessmentStats{
			Total:        10,
			ByStatus:     map[string]int{"compliant": 6, "non_compliant": 4},
			AvgRiskScore: &avg,
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal(Assessment): %v", err)
	}

	var decoded Assessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(Assessment): %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Status != "in_progress" {
		t.Errorf("Status: got %q, want in_progress", decoded.Status)
	}
	if decoded.Stats == nil {
		t.Fatal("Stats: got nil, want non-nil")
	}
	if decoded.Stats.Total != 10 {
		t.Errorf("Stats.Total: got %d, want 10", decoded.Stats.Total)
	}
	if decoded.Stats.AvgRiskScore == nil {
		t.Fatal("Stats.AvgRiskScore: got nil, want non-nil")
	}
	if *decoded.Stats.AvgRiskScore != avg {
		t.Errorf("Stats.AvgRiskScore: got %v, want %v", *decoded.Stats.AvgRiskScore, avg)
	}
	if decoded.CompletedAt != nil {
		t.Errorf("CompletedAt: got %v, want nil", decoded.CompletedAt)
	}
}

// Stats should be absent from JSON output when nil (omitempty).
func TestAssessment_OmitEmptyStats(t *testing.T) {
	a := Assessment{
		ID:        "asmt-002",
		OrgID:     "org-001",
		Title:     "Draft Assessment",
		Status:    "draft",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Stats:     nil,
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, ok := raw["stats"]; ok {
		t.Error("expected 'stats' to be omitted when nil, but it is present")
	}
}

// ----------------------------------------------------------------------------
// UploadSpecResponse — JSON tags
// ----------------------------------------------------------------------------

func TestUploadSpecResponse_JSONTags(t *testing.T) {
	resp := UploadSpecResponse{
		SpecPath: "/tmp/specs/openapi.yaml",
		SpecHash: "sha256:abc123",
		Size:     2048,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, key := range []string{"spec_path", "spec_hash", "size"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found in UploadSpecResponse", key)
		}
	}

	var decoded UploadSpecResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.SpecPath != resp.SpecPath {
		t.Errorf("SpecPath: got %q, want %q", decoded.SpecPath, resp.SpecPath)
	}
	if decoded.Size != resp.Size {
		t.Errorf("Size: got %d, want %d", decoded.Size, resp.Size)
	}
}

// ----------------------------------------------------------------------------
// RefreshTokenResponse — JSON tags
// ----------------------------------------------------------------------------

func TestRefreshTokenResponse_JSONTags(t *testing.T) {
	const jsonStr = `{"access_token":"tok_new","refresh_token":"ref_new","expires_in":3600}`
	var resp RefreshTokenResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.AccessToken != "tok_new" {
		t.Errorf("AccessToken: got %q, want tok_new", resp.AccessToken)
	}
	if resp.RefreshToken != "ref_new" {
		t.Errorf("RefreshToken: got %q, want ref_new", resp.RefreshToken)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn: got %d, want 3600", resp.ExpiresIn)
	}
}
