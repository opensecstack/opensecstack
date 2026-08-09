// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting_test

import (
	"testing"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/reporting"
)

func boolPtr(b bool) *bool { return &b }

func TestCalculateCoverage_Empty(t *testing.T) {
	report := reporting.CalculateCoverage(nil)
	if report.TotalRuns != 0 {
		t.Errorf("TotalRuns = %d, want 0", report.TotalRuns)
	}
	if report.OverallDetectionRate != 0 {
		t.Errorf("OverallDetectionRate = %v, want 0", report.OverallDetectionRate)
	}
	if len(report.Rows) != 0 {
		t.Errorf("Rows = %v, want empty", report.Rows)
	}
}

func TestCalculateCoverage_BucketsByNotes(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "bola", Detected: boolPtr(true)},
		{Notes: "bola", Detected: boolPtr(false)},
		{Notes: "BOLA", Detected: boolPtr(true)}, // same bucket, case-insensitive
		{Notes: "ssrf", Detected: boolPtr(false)},
	}
	report := reporting.CalculateCoverage(runs)

	if report.TotalRuns != 4 {
		t.Errorf("TotalRuns = %d, want 4", report.TotalRuns)
	}
	if report.TotalDetected != 2 {
		t.Errorf("TotalDetected = %d, want 2", report.TotalDetected)
	}
	if report.OverallDetectionRate != 0.5 {
		t.Errorf("OverallDetectionRate = %v, want 0.5", report.OverallDetectionRate)
	}
	if len(report.Rows) != 2 {
		t.Fatalf("expected 2 buckets (bola, ssrf), got %d: %+v", len(report.Rows), report.Rows)
	}

	// Rows are sorted ascending by DetectionRate, so ssrf (0%) comes first.
	if report.Rows[0].AttackKind != "ssrf" {
		t.Errorf("Rows[0].AttackKind = %q, want ssrf", report.Rows[0].AttackKind)
	}
	if report.Rows[0].DetectionRate != 0 {
		t.Errorf("Rows[0].DetectionRate = %v, want 0", report.Rows[0].DetectionRate)
	}
	if report.Rows[1].AttackKind != "bola" {
		t.Errorf("Rows[1].AttackKind = %q, want bola", report.Rows[1].AttackKind)
	}
	if report.Rows[1].TotalRuns != 3 {
		t.Errorf("Rows[1].TotalRuns = %d, want 3", report.Rows[1].TotalRuns)
	}
	if report.Rows[1].DetectedRuns != 2 {
		t.Errorf("Rows[1].DetectedRuns = %d, want 2", report.Rows[1].DetectedRuns)
	}
	if report.Rows[1].MissedRuns != 1 {
		t.Errorf("Rows[1].MissedRuns = %d, want 1", report.Rows[1].MissedRuns)
	}
	// bola row should carry the MITRE technique info.
	if report.Rows[1].TechniqueID != "T1078" {
		t.Errorf("Rows[1].TechniqueID = %q, want T1078", report.Rows[1].TechniqueID)
	}
}

func TestCalculateCoverage_FallsBackToScenarioID(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "", ScenarioID: "scenario-42", Detected: boolPtr(true)},
	}
	report := reporting.CalculateCoverage(runs)
	if len(report.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(report.Rows))
	}
	if report.Rows[0].AttackKind != "scenario-42" {
		t.Errorf("AttackKind = %q, want scenario-42", report.Rows[0].AttackKind)
	}
}

func TestCalculateCoverage_SkipsRunsWithNoKeyAtAll(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "", ScenarioID: "", Detected: boolPtr(true)},
	}
	report := reporting.CalculateCoverage(runs)
	if report.TotalRuns != 0 {
		t.Errorf("TotalRuns = %d, want 0 (run with no key should be skipped)", report.TotalRuns)
	}
}

func TestCalculateCoverage_NilDetectedTreatedAsMissed(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "ssrf", Detected: nil},
	}
	report := reporting.CalculateCoverage(runs)
	if report.TotalDetected != 0 {
		t.Errorf("TotalDetected = %d, want 0 for nil Detected", report.TotalDetected)
	}
	if report.Rows[0].MissedRuns != 1 {
		t.Errorf("MissedRuns = %d, want 1", report.Rows[0].MissedRuns)
	}
}
