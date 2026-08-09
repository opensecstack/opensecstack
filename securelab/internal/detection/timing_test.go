// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection_test

import (
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/detection"
)

func TestMeasureLatency_BasicCase(t *testing.T) {
	attackTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	alerts := []detection.AlertEvent{
		{Technique: "bola", Timestamp: attackTime.Add(5 * time.Second)},
	}
	lat := detection.MeasureLatency(attackTime, alerts)
	if lat["bola"] != 5*time.Second {
		t.Errorf("latency = %v, want 5s", lat["bola"])
	}
}

func TestMeasureLatency_UsesEarliestAlertPerTechnique(t *testing.T) {
	attackTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	alerts := []detection.AlertEvent{
		{Technique: "bola", Timestamp: attackTime.Add(10 * time.Second)},
		{Technique: "bola", Timestamp: attackTime.Add(3 * time.Second)}, // earlier — should win
		{Technique: "bola", Timestamp: attackTime.Add(7 * time.Second)},
	}
	lat := detection.MeasureLatency(attackTime, alerts)
	if lat["bola"] != 3*time.Second {
		t.Errorf("latency = %v, want 3s (earliest alert)", lat["bola"])
	}
}

func TestMeasureLatency_TechniqueCaseNormalised(t *testing.T) {
	attackTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	alerts := []detection.AlertEvent{
		{Technique: "BOLA", Timestamp: attackTime.Add(2 * time.Second)},
	}
	lat := detection.MeasureLatency(attackTime, alerts)
	if _, ok := lat["bola"]; !ok {
		t.Errorf("expected normalised key 'bola' in result, got %v", lat)
	}
}

func TestMeasureLatency_NegativeLatencyClampedToZero(t *testing.T) {
	attackTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	alerts := []detection.AlertEvent{
		{Technique: "bola", Timestamp: attackTime.Add(-5 * time.Second)}, // alert before attack
	}
	lat := detection.MeasureLatency(attackTime, alerts)
	if lat["bola"] != 0 {
		t.Errorf("latency = %v, want 0 (clamped)", lat["bola"])
	}
}

func TestMeasureLatency_EmptyTechniqueSkipped(t *testing.T) {
	attackTime := time.Now()
	alerts := []detection.AlertEvent{
		{Technique: "  ", Timestamp: attackTime.Add(time.Second)},
	}
	lat := detection.MeasureLatency(attackTime, alerts)
	if len(lat) != 0 {
		t.Errorf("expected empty result for blank technique, got %v", lat)
	}
}

func TestMeasureLatency_NoAlerts(t *testing.T) {
	lat := detection.MeasureLatency(time.Now(), nil)
	if len(lat) != 0 {
		t.Errorf("expected empty map, got %v", lat)
	}
}
