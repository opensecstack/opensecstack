// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection

import (
	"context"
	"strings"
)

// AttackResult is a minimal representation of a completed attack used by the
// verifier. The full type lives in each attack package; this interface-style
// struct avoids circular imports.
type AttackResult struct {
	Technique string
	Success   bool
}

// VerificationResult summarises how well the detection stack performed
// against a set of attack simulations.
type VerificationResult struct {
	DetectedCount      int
	MissedCount        int
	DetectedTechniques []string
	MissedTechniques   []string
	DetectionRate      float64
}

// Verify cross-references attack results with received alerts, determining
// which techniques were detected and which were missed. Only attacks that
// succeeded (i.e., found a vulnerability or generated traffic) are counted.
func Verify(_ context.Context, _ string, attackResults []AttackResult, alerts []AlertEvent) *VerificationResult {
	// Build a set of technique names seen in alerts.
	detected := make(map[string]struct{}, len(alerts))
	for _, a := range alerts {
		detected[normalise(a.Technique)] = struct{}{}
	}

	result := &VerificationResult{}

	for _, ar := range attackResults {
		if !ar.Success {
			// Skip attacks that did not produce exploitable traffic.
			continue
		}
		key := normalise(ar.Technique)
		if _, ok := detected[key]; ok {
			result.DetectedCount++
			result.DetectedTechniques = append(result.DetectedTechniques, ar.Technique)
		} else {
			result.MissedCount++
			result.MissedTechniques = append(result.MissedTechniques, ar.Technique)
		}
	}

	total := result.DetectedCount + result.MissedCount
	if total > 0 {
		result.DetectionRate = float64(result.DetectedCount) / float64(total)
	}

	return result
}

// normalise lowercases and strips common noise characters for comparison.
func normalise(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
