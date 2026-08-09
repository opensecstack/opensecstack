// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting_test

import (
	"strings"
	"testing"

	"github.com/opensecstack/securelab/internal/reporting"
)

func TestGenerateHTML_ContainsSummaryStats(t *testing.T) {
	report := reporting.CoverageReport{
		TotalRuns:            10,
		TotalDetected:        7,
		OverallDetectionRate: 0.7,
		Rows: []reporting.TechniqueRow{
			{AttackKind: "bola", TechniqueID: "T1078", TechniqueName: "Valid Accounts", TotalRuns: 10, DetectedRuns: 7, MissedRuns: 3, DetectionRate: 0.7},
		},
	}

	out, err := reporting.GenerateHTML(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	html := string(out)

	if !strings.HasPrefix(html, "<!DOCTYPE html>") {
		t.Error("expected output to start with <!DOCTYPE html>")
	}
	if !strings.Contains(html, "70.0%") {
		t.Errorf("expected overall detection rate 70.0%% in output")
	}
	if !strings.Contains(html, "bola") {
		t.Error("expected attack kind 'bola' in output")
	}
	if !strings.Contains(html, "T1078") {
		t.Error("expected technique ID T1078 in output")
	}
	if !strings.Contains(html, "10 scenario runs") {
		t.Error("expected run count in subtitle")
	}
}

func TestGenerateHTML_EscapesUserContent(t *testing.T) {
	report := reporting.CoverageReport{
		Rows: []reporting.TechniqueRow{
			{AttackKind: `<script>alert(1)</script>`, TechniqueName: "x", TotalRuns: 1, DetectedRuns: 0, MissedRuns: 1},
		},
	}
	out, err := reporting.GenerateHTML(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	html := string(out)
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("expected attack kind to be HTML-escaped, found raw script tag")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped script tag in output")
	}
}

func TestGenerateHTML_EmptyReport(t *testing.T) {
	out, err := reporting.GenerateHTML(reporting.CoverageReport{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "0.0%") {
		t.Error("expected 0.0% detection rate for empty report")
	}
}
