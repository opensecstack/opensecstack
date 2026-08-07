// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection

import (
	"sort"
	"strings"

	"github.com/opensecstack/securelab/internal/db"
)

// TechniqueStats holds aggregated detection statistics for a single technique.
type TechniqueStats struct {
	Technique     string
	TotalRuns     int
	DetectedRuns  int
	MissedRuns    int
	DetectionRate float64 // [0, 1]
	FalseNegRate  float64 // 1 - DetectionRate
}

// GapReport aggregates detection gaps across all historical scenario runs.
type GapReport struct {
	TechniqueStats        []TechniqueStats
	ConsistentlyMissed    []string // techniques with DetectionRate == 0
	HighFalseNegativeRate []string // techniques with FalseNegRate > 0.5
	OverallDetectionRate  float64
}

// AnalyzeGaps aggregates across all ScenarioRuns and identifies which MITRE
// techniques consistently evade detection or have high false-negative rates.
//
// Technique identity is derived from the run's Notes field (expected to contain
// the attack kind or MITRE ID) or falls back to the ScenarioID.
func AnalyzeGaps(runs []db.ScenarioRun) *GapReport {
	type bucket struct {
		total    int
		detected int
	}
	techMap := make(map[string]*bucket)

	for _, run := range runs {
		// Derive a technique key: prefer Notes (set by executor to attack kind),
		// fall back to ScenarioID so every run is counted.
		key := strings.ToLower(strings.TrimSpace(run.Notes))
		if key == "" {
			key = strings.ToLower(run.ScenarioID)
		}
		if key == "" {
			continue
		}

		b, ok := techMap[key]
		if !ok {
			b = &bucket{}
			techMap[key] = b
		}
		b.total++
		if run.Detected != nil && *run.Detected {
			b.detected++
		}
	}

	report := &GapReport{}
	var totalDetected, totalRuns int

	stats := make([]TechniqueStats, 0, len(techMap))
	for tech, b := range techMap {
		dr := 0.0
		if b.total > 0 {
			dr = float64(b.detected) / float64(b.total)
		}
		stats = append(stats, TechniqueStats{
			Technique:     tech,
			TotalRuns:     b.total,
			DetectedRuns:  b.detected,
			MissedRuns:    b.total - b.detected,
			DetectionRate: dr,
			FalseNegRate:  1 - dr,
		})
		totalDetected += b.detected
		totalRuns += b.total
	}

	// Sort by detection rate ascending (worst gaps first).
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].DetectionRate < stats[j].DetectionRate
	})
	report.TechniqueStats = stats

	for _, s := range stats {
		if s.DetectionRate == 0 && s.TotalRuns > 0 {
			report.ConsistentlyMissed = append(report.ConsistentlyMissed, s.Technique)
		}
		if s.FalseNegRate > 0.5 {
			report.HighFalseNegativeRate = append(report.HighFalseNegativeRate, s.Technique)
		}
	}

	if totalRuns > 0 {
		report.OverallDetectionRate = float64(totalDetected) / float64(totalRuns)
	}

	return report
}
