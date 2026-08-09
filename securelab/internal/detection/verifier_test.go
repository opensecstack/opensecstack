// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection_test

import (
	"context"
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/detection"
)

func TestVerify_DetectedAndMissed(t *testing.T) {
	attackResults := []detection.AttackResult{
		{Technique: "bola", Success: true},
		{Technique: "ssrf", Success: true},
	}
	alerts := []detection.AlertEvent{
		{Technique: "bola", Timestamp: time.Now()},
	}

	result := detection.Verify(context.Background(), "run-1", attackResults, alerts)

	if result.DetectedCount != 1 {
		t.Errorf("DetectedCount = %d, want 1", result.DetectedCount)
	}
	if result.MissedCount != 1 {
		t.Errorf("MissedCount = %d, want 1", result.MissedCount)
	}
	if len(result.DetectedTechniques) != 1 || result.DetectedTechniques[0] != "bola" {
		t.Errorf("DetectedTechniques = %v, want [bola]", result.DetectedTechniques)
	}
	if len(result.MissedTechniques) != 1 || result.MissedTechniques[0] != "ssrf" {
		t.Errorf("MissedTechniques = %v, want [ssrf]", result.MissedTechniques)
	}
	if result.DetectionRate != 0.5 {
		t.Errorf("DetectionRate = %v, want 0.5", result.DetectionRate)
	}
}

func TestVerify_UnsuccessfulAttacksSkipped(t *testing.T) {
	attackResults := []detection.AttackResult{
		{Technique: "bola", Success: false}, // attack itself failed — should not be counted at all
	}
	result := detection.Verify(context.Background(), "run-1", attackResults, nil)
	if result.DetectedCount != 0 || result.MissedCount != 0 {
		t.Errorf("expected unsuccessful attack to be skipped entirely, got detected=%d missed=%d",
			result.DetectedCount, result.MissedCount)
	}
	if result.DetectionRate != 0 {
		t.Errorf("DetectionRate = %v, want 0 for no counted attacks", result.DetectionRate)
	}
}

func TestVerify_TechniqueMatchCaseInsensitive(t *testing.T) {
	attackResults := []detection.AttackResult{{Technique: "BOLA", Success: true}}
	alerts := []detection.AlertEvent{{Technique: "bola", Timestamp: time.Now()}}
	result := detection.Verify(context.Background(), "run-1", attackResults, alerts)
	if result.DetectedCount != 1 {
		t.Errorf("expected case-insensitive match, DetectedCount = %d", result.DetectedCount)
	}
}

func TestVerify_NoAttacks(t *testing.T) {
	result := detection.Verify(context.Background(), "run-1", nil, nil)
	if result.DetectionRate != 0 {
		t.Errorf("DetectionRate = %v, want 0", result.DetectionRate)
	}
	if result.DetectedCount != 0 || result.MissedCount != 0 {
		t.Errorf("expected zero counts for no attacks")
	}
}

func TestVerify_AllDetected(t *testing.T) {
	attackResults := []detection.AttackResult{
		{Technique: "bola", Success: true},
		{Technique: "ssrf", Success: true},
	}
	alerts := []detection.AlertEvent{
		{Technique: "bola", Timestamp: time.Now()},
		{Technique: "ssrf", Timestamp: time.Now()},
	}
	result := detection.Verify(context.Background(), "run-1", attackResults, alerts)
	if result.DetectionRate != 1.0 {
		t.Errorf("DetectionRate = %v, want 1.0", result.DetectionRate)
	}
}
