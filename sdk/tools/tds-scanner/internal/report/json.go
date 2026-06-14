package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/opensecstack/tds-scanner/internal/checks"
)

// jsonFinding is the wire representation of a Finding in JSON output.
type jsonFinding struct {
	CheckID     string `json:"check_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	FilePath    string `json:"file_path"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Snippet     string `json:"snippet"`
	Remediation string `json:"remediation"`
}

// jsonSummary is the summary block in the JSON report.
type jsonSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// jsonReport is the top-level JSON report structure.
type jsonReport struct {
	SchemaVersion string        `json:"schema_version"`
	Target        string        `json:"target"`
	Language      string        `json:"language"`
	ChecksRun     int           `json:"checks_run"`
	Findings      []jsonFinding `json:"findings"`
	Summary       jsonSummary   `json:"summary"`
	Result        string        `json:"result"`
	ScannedAt     string        `json:"scanned_at"`
}

// WriteJSON writes a structured JSON report to w.
func WriteJSON(
	w io.Writer,
	target string,
	language string,
	checksRun int,
	findings []checks.Finding,
	result string,
) error {
	// Convert findings to the wire type.
	jFindings := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		jFindings = append(jFindings, jsonFinding{
			CheckID:     f.CheckID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			FilePath:    f.FilePath,
			Line:        f.Line,
			Column:      f.Column,
			Snippet:     f.Snippet,
			Remediation: f.Remediation,
		})
	}

	counts := summaryCounts(findings)
	report := jsonReport{
		SchemaVersion: "1.0",
		Target:        target,
		Language:      language,
		ChecksRun:     checksRun,
		Findings:      jFindings,
		Summary: jsonSummary{
			Critical: counts["critical"],
			High:     counts["high"],
			Medium:   counts["medium"],
			Low:      counts["low"],
			Info:     counts["info"],
		},
		Result:    result,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
