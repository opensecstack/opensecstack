package integration_test

import (
	"testing"
	"time"
)

// MockAttackResult represents the outcome of a single attack step.
type MockAttackResult struct {
	ScenarioName  string
	StepKind      string
	MITRETechnique string
	StartedAt     time.Time
	CompletedAt   time.Time
	Success       bool
}

// MockAlert represents a detection alert from a detection platform.
type MockAlert struct {
	Platform      string
	MITRETechnique string
	ReceivedAt    time.Time
	EnvironmentID string
}

// DetectionSummary is the output of Verify.
type DetectionSummary struct {
	TotalSteps    int
	DetectedCount int
	DetectionRate float64 // 0.0 to 1.0
	Gaps          []string
}

// Verify compares attack results against alerts and returns a detection summary.
// A step is considered detected if there is at least one alert matching the
// MITRE technique ID received within the detection window after the step started.
func Verify(results []MockAttackResult, alerts []MockAlert, windowDuration time.Duration) DetectionSummary {
	detected := 0
	var gaps []string

	for _, result := range results {
		if !result.Success {
			continue
		}
		windowEnd := result.CompletedAt.Add(windowDuration)
		found := false
		for _, alert := range alerts {
			if alert.MITRETechnique == result.MITRETechnique &&
				!alert.ReceivedAt.Before(result.StartedAt) &&
				alert.ReceivedAt.Before(windowEnd) {
				found = true
				break
			}
		}
		if found {
			detected++
		} else {
			gaps = append(gaps, result.MITRETechnique)
		}
	}

	total := len(results)
	var rate float64
	if total > 0 {
		rate = float64(detected) / float64(total)
	}

	return DetectionSummary{
		TotalSteps:    total,
		DetectedCount: detected,
		DetectionRate: rate,
		Gaps:          gaps,
	}
}

// TestDetectionVerify_AllDetected verifies that when matching alerts exist for
// all attack steps, the detection rate is 1.0 and no gaps are reported.
func TestDetectionVerify_AllDetected(t *testing.T) {
	now := time.Now()
	results := []MockAttackResult{
		{
			ScenarioName:   "bola-basic",
			StepKind:       "bola",
			MITRETechnique: "T1078",
			StartedAt:      now,
			CompletedAt:    now.Add(2 * time.Second),
			Success:        true,
		},
		{
			ScenarioName:   "jwt-none",
			StepKind:       "jwt_none",
			MITRETechnique: "T1078.001",
			StartedAt:      now.Add(5 * time.Second),
			CompletedAt:    now.Add(6 * time.Second),
			Success:        true,
		},
	}

	alerts := []MockAlert{
		{Platform: "apiguard", MITRETechnique: "T1078", ReceivedAt: now.Add(3 * time.Second)},
		{Platform: "apiguard", MITRETechnique: "T1078.001", ReceivedAt: now.Add(8 * time.Second)},
	}

	summary := Verify(results, alerts, 60*time.Second)

	if summary.DetectionRate != 1.0 {
		t.Errorf("Expected detection rate 1.0, got %f", summary.DetectionRate)
	}
	if len(summary.Gaps) != 0 {
		t.Errorf("Expected no gaps, got %v", summary.Gaps)
	}
	if summary.DetectedCount != 2 {
		t.Errorf("Expected 2 detected, got %d", summary.DetectedCount)
	}
}

// TestDetectionVerify_PartialDetection verifies that detection gaps are correctly
// identified when only some steps have matching alerts.
func TestDetectionVerify_PartialDetection(t *testing.T) {
	now := time.Now()
	results := []MockAttackResult{
		{
			MITRETechnique: "T1078",
			StartedAt:      now,
			CompletedAt:    now.Add(1 * time.Second),
			Success:        true,
		},
		{
			MITRETechnique: "T1046",
			StartedAt:      now.Add(5 * time.Second),
			CompletedAt:    now.Add(6 * time.Second),
			Success:        true,
		},
	}

	// Only T1078 has an alert; T1046 (port scan) is not detected
	alerts := []MockAlert{
		{Platform: "openscrub", MITRETechnique: "T1078", ReceivedAt: now.Add(2 * time.Second)},
	}

	summary := Verify(results, alerts, 60*time.Second)

	if summary.DetectionRate != 0.5 {
		t.Errorf("Expected detection rate 0.5, got %f", summary.DetectionRate)
	}
	if len(summary.Gaps) != 1 {
		t.Errorf("Expected 1 gap, got %d: %v", len(summary.Gaps), summary.Gaps)
	}
	if summary.Gaps[0] != "T1046" {
		t.Errorf("Expected gap for T1046, got %s", summary.Gaps[0])
	}
}

// TestDetectionVerify_AlertOutsideWindow verifies that alerts received after the
// detection window closes do not count as detections.
func TestDetectionVerify_AlertOutsideWindow(t *testing.T) {
	now := time.Now()
	results := []MockAttackResult{
		{
			MITRETechnique: "T1078",
			StartedAt:      now,
			CompletedAt:    now.Add(1 * time.Second),
			Success:        true,
		},
	}

	// Alert arrives 2 minutes after step completed — outside a 60s window
	alerts := []MockAlert{
		{Platform: "openscrub", MITRETechnique: "T1078", ReceivedAt: now.Add(3 * time.Minute)},
	}

	summary := Verify(results, alerts, 60*time.Second)

	if summary.DetectionRate != 0.0 {
		t.Errorf("Expected detection rate 0.0 (alert outside window), got %f", summary.DetectionRate)
	}
	if len(summary.Gaps) != 1 {
		t.Errorf("Expected 1 gap, got %d", len(summary.Gaps))
	}
}
