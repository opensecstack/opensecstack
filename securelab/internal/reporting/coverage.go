// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting

import (
	"sort"
	"strings"

	"github.com/opensecstack/securelab/internal/db"
)

// TechniqueRow holds per-technique detection statistics for a coverage report.
type TechniqueRow struct {
	AttackKind    string
	TechniqueID   string  // MITRE ATT&CK ID
	TechniqueName string
	TotalRuns     int
	DetectedRuns  int
	MissedRuns    int
	DetectionRate float64 // [0, 1]
}

// CoverageReport aggregates detection coverage across all scenario runs.
type CoverageReport struct {
	Rows                 []TechniqueRow
	TotalRuns            int
	TotalDetected        int
	OverallDetectionRate float64 // [0, 1]
}

// CalculateCoverage aggregates runs by attack kind (stored in Notes) and
// calculates the detection rate per technique and the overall coverage.
//
// The run's Notes field is expected to hold the attack kind string (set by the
// executor). Runs without Notes are bucketed under their ScenarioID.
func CalculateCoverage(runs []db.ScenarioRun) CoverageReport {
	type bucket struct {
		total    int
		detected int
	}
	kindMap := make(map[string]*bucket)

	for _, r := range runs {
		key := strings.ToLower(strings.TrimSpace(r.Notes))
		if key == "" {
			key = strings.ToLower(r.ScenarioID)
		}
		if key == "" {
			continue
		}

		b, ok := kindMap[key]
		if !ok {
			b = &bucket{}
			kindMap[key] = b
		}
		b.total++
		if r.Detected != nil && *r.Detected {
			b.detected++
		}
	}

	rows := make([]TechniqueRow, 0, len(kindMap))
	var totalRuns, totalDetected int

	for kind, b := range kindMap {
		row := TechniqueRow{
			AttackKind:   kind,
			TotalRuns:    b.total,
			DetectedRuns: b.detected,
			MissedRuns:   b.total - b.detected,
		}
		if b.total > 0 {
			row.DetectionRate = float64(b.detected) / float64(b.total)
		}
		if entry, ok := LookupByKind(kind); ok {
			row.TechniqueID = entry.TechniqueID
			row.TechniqueName = entry.Name
		}
		rows = append(rows, row)
		totalRuns += b.total
		totalDetected += b.detected
	}

	// Sort by detection rate ascending so gaps appear first.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].DetectionRate < rows[j].DetectionRate
	})

	report := CoverageReport{
		Rows:          rows,
		TotalRuns:     totalRuns,
		TotalDetected: totalDetected,
	}
	if totalRuns > 0 {
		report.OverallDetectionRate = float64(totalDetected) / float64(totalRuns)
	}
	return report
}
