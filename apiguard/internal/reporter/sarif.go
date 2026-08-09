package reporter

import (
	"encoding/json"
	"strings"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/version"
)

// SARIFReporter produces SARIF v2.1.0 reports compatible with the GitHub
// Security tab and other SARIF consumers.
type SARIFReporter struct{}

// sarifModuleMapping maps internal module IDs to SARIF rule IDs.
var sarifModuleMapping = map[string]string{
	"a1_bola":                "apiguard/a1-bola",
	"a2_auth":                "apiguard/a2-broken-auth",
	"a3_mass_assignment":     "apiguard/a3-property-auth",
	"a4_rate_limiting":       "apiguard/a4-resource-consumption",
	"a5_function_auth":       "apiguard/a5-function-auth",
	"a6_business_flow":       "apiguard/a6-business-flow",
	"a7_ssrf":                "apiguard/a7-ssrf",
	"a8_misconfig":           "apiguard/a8-misconfig",
	"a9_inventory":           "apiguard/a9-inventory",
	"a10_unsafe_consumption": "apiguard/a10-unsafe-consumption",
}

// SARIF schema types. These follow the OASIS SARIF v2.1.0 specification.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	Help             sarifHelp           `json:"help"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRuleProperties struct {
	OWASPId string `json:"owasp_id"`
}

type sarifResult struct {
	RuleID     string                `json:"ruleId"`
	Level      string                `json:"level"`
	Message    sarifMessage          `json:"message"`
	Locations  []sarifLocation       `json:"locations"`
	Properties sarifResultProperties `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation   `json:"physicalLocation"`
	Properties       sarifLocationProperties `json:"properties"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifLocationProperties struct {
	Method string `json:"method"`
}

type sarifResultProperties struct {
	CVSSScore  float64              `json:"cvss_score"`
	CVSSVector string               `json:"cvss_vector"`
	Evidence   sarifEvidenceCompact `json:"evidence"`
}

type sarifEvidenceCompact struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

// Generate produces a SARIF v2.1.0 JSON report.
func (r *SARIFReporter) Generate(result *domain.ScanResult) ([]byte, error) {
	rules := buildSARIFRules(result.Findings)
	results := buildSARIFResults(result.Findings)

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "APIGuard",
						Version:        version.Version,
						InformationURI: "https://github.com/opensecstack/apiguard",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}

// buildSARIFRules creates SARIF rule definitions from the modules referenced
// in the findings. Each unique module produces exactly one rule entry.
func buildSARIFRules(findings []domain.Finding) []sarifRule {
	seen := make(map[string]struct{})
	var rules []sarifRule

	// Also include rules for all default modules so the SARIF consumer knows
	// about the full rule set.
	for _, mod := range domain.DefaultModules {
		ruleID, ok := sarifModuleMapping[mod.ID]
		if !ok {
			continue
		}
		if _, exists := seen[mod.ID]; exists {
			continue
		}
		seen[mod.ID] = struct{}{}

		ruleName := sarifRuleName(mod.Name)
		rules = append(rules, sarifRule{
			ID:   ruleID,
			Name: ruleName,
			ShortDescription: sarifMessage{
				Text: mod.Name + " (OWASP " + mod.OWASPId + ")",
			},
			Help: sarifHelp{
				Text:     mod.Description,
				Markdown: "**" + mod.Name + "** -- OWASP " + mod.OWASPId,
			},
			Properties: sarifRuleProperties{
				OWASPId: mod.OWASPId,
			},
		})
	}

	// Add any rules from findings whose module was not in DefaultModules.
	for _, f := range findings {
		if _, exists := seen[f.ModuleID]; exists {
			continue
		}
		seen[f.ModuleID] = struct{}{}

		ruleID := sarifModuleMapping[f.ModuleID]
		if ruleID == "" {
			ruleID = "apiguard/" + f.ModuleID
		}
		rules = append(rules, sarifRule{
			ID:   ruleID,
			Name: sarifRuleName(f.Title),
			ShortDescription: sarifMessage{
				Text: f.Title + " (OWASP " + f.OWASPId + ")",
			},
			Help: sarifHelp{
				Text:     f.Remediation,
				Markdown: "**Remediation**: " + f.Remediation,
			},
			Properties: sarifRuleProperties{
				OWASPId: f.OWASPId,
			},
		})
	}

	return rules
}

// buildSARIFResults maps findings to SARIF result objects.
func buildSARIFResults(findings []domain.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := sarifModuleMapping[f.ModuleID]
		if ruleID == "" {
			ruleID = "apiguard/" + f.ModuleID
		}

		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Title + " at " + f.EndpointMethod + " " + f.EndpointPath,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:       f.EndpointPath,
							URIBaseID: "API_ROOT",
						},
					},
					Properties: sarifLocationProperties{
						Method: f.EndpointMethod,
					},
				},
			},
			Properties: sarifResultProperties{
				CVSSScore:  f.CVSSScore,
				CVSSVector: f.CVSSVector,
				Evidence: sarifEvidenceCompact{
					Request:  f.Evidence.Request,
					Response: f.Evidence.Response,
				},
			},
		})
	}

	return results
}

// severityToSARIFLevel maps APIGuard severity to SARIF level.
// critical/high -> error, medium -> warning, low/info -> note.
func severityToSARIFLevel(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	case domain.SeverityLow, domain.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

// sarifRuleName converts a human-readable name to PascalCase for SARIF.
func sarifRuleName(name string) string {
	words := strings.Fields(name)
	var b strings.Builder
	for _, w := range words {
		if len(w) == 0 {
			continue
		}
		b.WriteString(strings.ToUpper(w[:1]))
		if len(w) > 1 {
			b.WriteString(w[1:])
		}
	}
	return b.String()
}
