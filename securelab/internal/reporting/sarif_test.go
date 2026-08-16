// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting_test

import (
	"encoding/json"
	"testing"

	"github.com/opensecstack/securelab/internal/reporting"
)

func TestGenerateSARIF_ValidJSONWithSchemaAndVersion(t *testing.T) {
	report := reporting.CoverageReport{
		Rows: []reporting.TechniqueRow{
			{AttackKind: "bola", TechniqueID: "T1078", TechniqueName: "Valid Accounts", TotalRuns: 4, DetectedRuns: 0, MissedRuns: 4, DetectionRate: 0},
		},
	}

	out, err := reporting.GenerateSARIF(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
	if doc["$schema"] == "" || doc["$schema"] == nil {
		t.Error("expected non-empty $schema")
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run, got %v", doc["runs"])
	}
}

func TestGenerateSARIF_OneRulePerMissedTechnique(t *testing.T) {
	report := reporting.CoverageReport{
		Rows: []reporting.TechniqueRow{
			{AttackKind: "bola", TechniqueID: "T1078", TotalRuns: 4, DetectedRuns: 4, MissedRuns: 0, DetectionRate: 1.0},          // fully detected -> no rule
			{AttackKind: "ssrf", TechniqueID: "T1090", TotalRuns: 4, DetectedRuns: 0, MissedRuns: 4, DetectionRate: 0},            // never detected -> rule, error level
			{AttackKind: "udpflood", TechniqueID: "T1498.001", TotalRuns: 4, DetectedRuns: 3, MissedRuns: 1, DetectionRate: 0.75}, // partially missed -> rule, note level
		},
	}

	out, err := reporting.GenerateSARIF(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rules := doc.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (ssrf + udpflood), got %d: %+v", len(rules), rules)
	}

	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	levelByRule := map[string]string{}
	for _, r := range results {
		levelByRule[r.RuleID] = r.Level
	}
	if levelByRule["SL-ssrf"] != "error" {
		t.Errorf("SL-ssrf level = %q, want error (0%% detection)", levelByRule["SL-ssrf"])
	}
	if levelByRule["SL-udpflood"] != "note" {
		t.Errorf("SL-udpflood level = %q, want note (75%% detection)", levelByRule["SL-udpflood"])
	}
}

func TestGenerateSARIF_NoMissedTechniquesProducesNoRules(t *testing.T) {
	report := reporting.CoverageReport{
		Rows: []reporting.TechniqueRow{
			{AttackKind: "bola", TotalRuns: 5, DetectedRuns: 5, MissedRuns: 0, DetectionRate: 1.0},
		},
	}
	out, err := reporting.GenerateSARIF(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(doc.Runs[0].Results))
	}
}
