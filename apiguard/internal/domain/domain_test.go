package domain

import "testing"

func TestScanStatusConstants(t *testing.T) {
	statuses := []ScanStatus{
		ScanStatusPending,
		ScanStatusRunning,
		ScanStatusCompleted,
		ScanStatusFailed,
		ScanStatusCancelled,
	}
	for _, s := range statuses {
		if s == "" {
			t.Error("ScanStatus constant must not be empty")
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	severities := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
	for _, s := range severities {
		if s == "" {
			t.Error("Severity constant must not be empty")
		}
	}
}

func TestFindingStatusConstants(t *testing.T) {
	statuses := []FindingStatus{
		FindingStatusOpen,
		FindingStatusConfirmed,
		FindingStatusFalsePositive,
		FindingStatusAccepted,
		FindingStatusFixed,
	}
	for _, s := range statuses {
		if s == "" {
			t.Error("FindingStatus constant must not be empty")
		}
	}
}

func TestDefaultModules(t *testing.T) {
	if len(DefaultModules) != 10 {
		t.Errorf("DefaultModules length = %d, want 10", len(DefaultModules))
	}

	// Verify all modules have required fields set.
	for i, mod := range DefaultModules {
		if mod.ID == "" {
			t.Errorf("DefaultModules[%d].ID is empty", i)
		}
		if mod.OWASPId == "" {
			t.Errorf("DefaultModules[%d].OWASPId is empty", i)
		}
		if mod.Name == "" {
			t.Errorf("DefaultModules[%d].Name is empty", i)
		}
	}

	// Verify a6 and a10 are disabled by default.
	for _, mod := range DefaultModules {
		if mod.ID == "a6_business_flow" && mod.Enabled {
			t.Error("a6_business_flow should be disabled by default")
		}
		if mod.ID == "a10_unsafe_consumption" && mod.Enabled {
			t.Error("a10_unsafe_consumption should be disabled by default")
		}
	}
}
