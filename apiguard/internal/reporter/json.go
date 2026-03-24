package reporter

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/version"
)

// JSONReporter produces machine-readable JSON reports.
type JSONReporter struct{}

// jsonReport is the top-level JSON output structure.
type jsonReport struct {
	Scan     jsonScan      `json:"scan"`
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
	Metadata jsonMetadata  `json:"metadata"`
}

type jsonScan struct {
	ID          string `json:"id"`
	Target      string `json:"target"`
	SpecHash    string `json:"spec_hash"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Status      string `json:"status"`
}

type jsonSummary struct {
	Total          int      `json:"total"`
	Critical       int      `json:"critical"`
	High           int      `json:"high"`
	Medium         int      `json:"medium"`
	Low            int      `json:"low"`
	Info           int      `json:"info"`
	ModulesEnabled []string `json:"modules_enabled"`
}

type jsonFinding struct {
	ID          string       `json:"id"`
	OWASPId     string       `json:"owasp_id"`
	ModuleID    string       `json:"module_id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	CVSSScore   float64      `json:"cvss_score"`
	CVSSVector  string       `json:"cvss_vector"`
	Endpoint    string       `json:"endpoint"`
	Method      string       `json:"method"`
	Evidence    jsonEvidence `json:"evidence"`
	Remediation string       `json:"remediation"`
	Status      string       `json:"status"`
}

type jsonEvidence struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type jsonMetadata struct {
	APIGuardVersion   string `json:"apiguard_version"`
	ScanDuration      string `json:"scan_duration"`
	ReportGeneratedAt string `json:"report_generated_at"`
}

// Generate produces a JSON report from the scan result.
func (r *JSONReporter) Generate(result *domain.ScanResult) ([]byte, error) {
	modulesEnabled := enabledModuleIDs(result.Findings)

	findings := make([]jsonFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, jsonFinding{
			ID:          f.ID,
			OWASPId:     f.OWASPId,
			ModuleID:    f.ModuleID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    strings.ToUpper(string(f.Severity)),
			CVSSScore:   f.CVSSScore,
			CVSSVector:  f.CVSSVector,
			Endpoint:    f.EndpointPath,
			Method:      f.EndpointMethod,
			Evidence: jsonEvidence{
				Request:  f.Evidence.Request,
				Response: f.Evidence.Response,
			},
			Remediation: f.Remediation,
			Status:      string(f.Status),
		})
	}

	duration := result.CompletedAt.Sub(result.StartedAt)

	report := jsonReport{
		Scan: jsonScan{
			ID:          result.ID,
			Target:      result.Target,
			SpecHash:    result.SpecHash,
			StartedAt:   result.StartedAt.Format(time.RFC3339),
			CompletedAt: result.CompletedAt.Format(time.RFC3339),
			Status:      string(result.Status),
		},
		Summary: jsonSummary{
			Total:          result.Summary.TotalFindings,
			Critical:       result.Summary.Critical,
			High:           result.Summary.High,
			Medium:         result.Summary.Medium,
			Low:            result.Summary.Low,
			Info:           result.Summary.Info,
			ModulesEnabled: modulesEnabled,
		},
		Findings: findings,
		Metadata: jsonMetadata{
			APIGuardVersion:   version.Version,
			ScanDuration:      duration.String(),
			ReportGeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

// enabledModuleIDs extracts the unique set of module IDs from findings.
func enabledModuleIDs(findings []domain.Finding) []string {
	seen := make(map[string]struct{})
	var modules []string
	for _, f := range findings {
		if _, ok := seen[f.ModuleID]; !ok {
			seen[f.ModuleID] = struct{}{}
			modules = append(modules, f.ModuleID)
		}
	}
	return modules
}
