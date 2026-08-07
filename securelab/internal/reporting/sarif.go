// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting

import (
	"encoding/json"
	"fmt"
	"time"
)

// GenerateSARIF produces a SARIF 2.1.0 JSON document with one rule per
// undetected (or poorly detected) technique. The output can be uploaded to
// GitHub Advanced Security or any SARIF-compatible CI/CD tool.
func GenerateSARIF(report CoverageReport) ([]byte, error) {
	rules := buildSARIFRules(report)
	results := buildSARIFResults(report, rules)

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "SecureLab",
						Version:         "1.0.0",
						InformationURI:  "https://github.com/opensecstack/securelab",
						Organization:    "opensecstack",
						Rules:           rules,
					},
				},
				Results: results,
				Invocations: []sarifInvocation{
					{
						ExecutionSuccessful: true,
						StartTimeUTC:        time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}

// buildSARIFRules creates one SARIF rule per attack kind that has at least one
// missed detection.
func buildSARIFRules(report CoverageReport) []sarifRule {
	var rules []sarifRule
	for _, row := range report.Rows {
		if row.MissedRuns == 0 {
			continue
		}
		entry, _ := LookupByKind(row.AttackKind)
		helpURI := entry.URL
		if helpURI == "" {
			helpURI = "https://github.com/opensecstack/securelab"
		}

		rule := sarifRule{
			ID:   fmt.Sprintf("SL-%s", row.AttackKind),
			Name: fmt.Sprintf("UndetectedAttack/%s", row.AttackKind),
			ShortDescription: sarifMessage{
				Text: fmt.Sprintf("Attack technique '%s' not consistently detected", row.AttackKind),
			},
			FullDescription: sarifMessage{
				Text: fmt.Sprintf(
					"The '%s' attack technique (%s — %s) was missed in %d of %d simulation runs (detection rate %.1f%%). "+
						"Review detection rules for this attack pattern.",
					row.AttackKind, row.TechniqueID, row.TechniqueName,
					row.MissedRuns, row.TotalRuns, row.DetectionRate*100,
				),
			},
			HelpURI:          helpURI,
			DefaultLevel:     sarifDefaultLevel(row.DetectionRate),
			Properties: sarifProperties{
				Tags:             []string{"security", "detection", "mitre-attack", entry.TechniqueID},
				DetectionRate:    row.DetectionRate,
				MITRETechniqueID: row.TechniqueID,
				Tactic:           entry.Tactic,
			},
		}
		rules = append(rules, rule)
	}
	return rules
}

// buildSARIFResults creates one SARIF result per rule, pointing to the
// virtual "securelab/coverage" location.
func buildSARIFResults(report CoverageReport, rules []sarifRule) []sarifResult {
	var results []sarifResult
	for _, rule := range rules {
		result := sarifResult{
			RuleID:  rule.ID,
			Level:   rule.DefaultLevel,
			Message: sarifMessage{Text: rule.FullDescription.Text},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:       "securelab://coverage",
							URIBaseID: "%SRCROOT%",
						},
						Region: sarifRegion{StartLine: 1},
					},
				},
			},
		}
		results = append(results, result)
	}
	return results
}

// sarifDefaultLevel maps a detection rate to a SARIF severity level.
func sarifDefaultLevel(rate float64) string {
	switch {
	case rate == 0:
		return "error"
	case rate < 0.5:
		return "warning"
	default:
		return "note"
	}
}

// ---- SARIF 2.1.0 type definitions ----

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Organization   string      `json:"organization"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	HelpURI          string          `json:"helpUri"`
	DefaultLevel     string          `json:"defaultConfiguration.level,omitempty"`
	Properties       sarifProperties `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifProperties struct {
	Tags             []string `json:"tags,omitempty"`
	DetectionRate    float64  `json:"detectionRate"`
	MITRETechniqueID string   `json:"mitreTechniqueId,omitempty"`
	Tactic           string   `json:"tactic,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc"`
}
