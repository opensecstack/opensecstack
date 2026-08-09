// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection_test

import (
	"testing"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/detection"
)

func boolPtr(b bool) *bool { return &b }

func TestAnalyzeGaps_Empty(t *testing.T) {
	report := detection.AnalyzeGaps(nil)
	if report.OverallDetectionRate != 0 {
		t.Errorf("OverallDetectionRate = %v, want 0", report.OverallDetectionRate)
	}
	if len(report.TechniqueStats) != 0 {
		t.Errorf("expected no technique stats, got %v", report.TechniqueStats)
	}
	if len(report.ConsistentlyMissed) != 0 {
		t.Errorf("expected no consistently missed, got %v", report.ConsistentlyMissed)
	}
}

func TestAnalyzeGaps_ConsistentlyMissed(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "ssrf", Detected: boolPtr(false)},
		{Notes: "ssrf", Detected: boolPtr(false)},
	}
	report := detection.AnalyzeGaps(runs)
	if len(report.ConsistentlyMissed) != 1 || report.ConsistentlyMissed[0] != "ssrf" {
		t.Errorf("ConsistentlyMissed = %v, want [ssrf]", report.ConsistentlyMissed)
	}
	if report.TechniqueStats[0].DetectionRate != 0 {
		t.Errorf("DetectionRate = %v, want 0", report.TechniqueStats[0].DetectionRate)
	}
	if report.TechniqueStats[0].FalseNegRate != 1 {
		t.Errorf("FalseNegRate = %v, want 1", report.TechniqueStats[0].FalseNegRate)
	}
}

func TestAnalyzeGaps_HighFalseNegativeRate(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "bola", Detected: boolPtr(true)},
		{Notes: "bola", Detected: boolPtr(false)},
		{Notes: "bola", Detected: boolPtr(false)},
		{Notes: "bola", Detected: boolPtr(false)}, // 25% detected, 75% false neg > 0.5
	}
	report := detection.AnalyzeGaps(runs)
	if len(report.HighFalseNegativeRate) != 1 || report.HighFalseNegativeRate[0] != "bola" {
		t.Errorf("HighFalseNegativeRate = %v, want [bola]", report.HighFalseNegativeRate)
	}
	// Not consistently missed since detection rate > 0.
	if len(report.ConsistentlyMissed) != 0 {
		t.Errorf("ConsistentlyMissed = %v, want empty (some detections occurred)", report.ConsistentlyMissed)
	}
}

func TestAnalyzeGaps_FullyDetectedNotFlagged(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "bola", Detected: boolPtr(true)},
		{Notes: "bola", Detected: boolPtr(true)},
	}
	report := detection.AnalyzeGaps(runs)
	if len(report.ConsistentlyMissed) != 0 {
		t.Errorf("ConsistentlyMissed = %v, want empty", report.ConsistentlyMissed)
	}
	if len(report.HighFalseNegativeRate) != 0 {
		t.Errorf("HighFalseNegativeRate = %v, want empty", report.HighFalseNegativeRate)
	}
	if report.OverallDetectionRate != 1 {
		t.Errorf("OverallDetectionRate = %v, want 1", report.OverallDetectionRate)
	}
}

func TestAnalyzeGaps_SortedAscendingByDetectionRate(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "high", Detected: boolPtr(true)},
		{Notes: "low", Detected: boolPtr(false)},
	}
	report := detection.AnalyzeGaps(runs)
	if len(report.TechniqueStats) != 2 {
		t.Fatalf("expected 2 techniques, got %d", len(report.TechniqueStats))
	}
	if report.TechniqueStats[0].Technique != "low" {
		t.Errorf("expected 'low' (0%% detection) first, got %q", report.TechniqueStats[0].Technique)
	}
	if report.TechniqueStats[1].Technique != "high" {
		t.Errorf("expected 'high' (100%% detection) second, got %q", report.TechniqueStats[1].Technique)
	}
}

func TestAnalyzeGaps_SkipsRunsWithNoKey(t *testing.T) {
	runs := []db.ScenarioRun{
		{Notes: "", ScenarioID: "", Detected: boolPtr(true)},
	}
	report := detection.AnalyzeGaps(runs)
	if len(report.TechniqueStats) != 0 {
		t.Errorf("expected run with no key to be skipped, got %v", report.TechniqueStats)
	}
}
