package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/opensecstack/vertguard/internal/identity"
	"github.com/opensecstack/vertguard/internal/media"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/opensecstack/vertguard/internal/version"
)

// sarifLevel maps VertGuard classifications to SARIF result levels.
func sarifLevel(classification string) string {
	switch classification {
	case "BLOCKED":
		return "error"
	case "SUSPICIOUS":
		return "warning"
	default:
		return "note"
	}
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func generateSARIF(w io.Writer, r Report) error {
	results := extractSARIFResults(r)

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "VertGuard",
						Version: version.Version,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("reporter: sarif encode: %w", err)
	}
	return nil
}

func extractSARIFResults(r Report) []sarifResult {
	switch v := r.Result.(type) {
	case *prompt.ScanResult:
		return promptSARIFResults(v)
	case prompt.ScanResult:
		return promptSARIFResults(&v)
	case *phishing.ScanResult:
		return phishingSARIFResults(v)
	case phishing.ScanResult:
		return phishingSARIFResults(&v)
	case *identity.ScanResult:
		return identitySARIFResults(v)
	case identity.ScanResult:
		return identitySARIFResults(&v)
	case *media.Result:
		return mediaSARIFResults(v)
	case media.Result:
		return mediaSARIFResults(&v)
	}
	// Unknown result type: emit a single informational result.
	return []sarifResult{
		{
			RuleID:  "vertguard/unknown",
			Level:   "note",
			Message: sarifMessage{Text: fmt.Sprintf("scan_type=%s result type not recognised by SARIF formatter", r.ScanType)},
		},
	}
}

func promptSARIFResults(res *prompt.ScanResult) []sarifResult {
	if len(res.Matches) == 0 {
		return []sarifResult{
			{
				RuleID:  "vertguard/prompt/clean",
				Level:   sarifLevel(string(res.Classification)),
				Message: sarifMessage{Text: fmt.Sprintf("scan_id=%s classification=%s confidence=%.3f", res.ScanID, res.Classification, res.Confidence)},
			},
		}
	}
	out := make([]sarifResult, 0, len(res.Matches))
	for _, m := range res.Matches {
		out = append(out, sarifResult{
			RuleID: m.PatternID,
			Level:  sarifLevel(string(res.Classification)),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s — %s (confidence=%.3f)", m.PatternID, m.Description, m.Confidence),
			},
		})
	}
	return out
}

func phishingSARIFResults(res *phishing.ScanResult) []sarifResult {
	if len(res.Matches) == 0 {
		return []sarifResult{
			{
				RuleID:  "vertguard/phishing/clean",
				Level:   sarifLevel(string(res.Classification)),
				Message: sarifMessage{Text: fmt.Sprintf("scan_id=%s classification=%s confidence=%.3f", res.ScanID, res.Classification, res.Confidence)},
			},
		}
	}
	out := make([]sarifResult, 0, len(res.Matches))
	for _, m := range res.Matches {
		out = append(out, sarifResult{
			RuleID: m.PatternID,
			Level:  sarifLevel(string(res.Classification)),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s — %s (confidence=%.3f)", m.PatternID, m.Description, m.Confidence),
			},
		})
	}
	return out
}

func identitySARIFResults(res *identity.ScanResult) []sarifResult {
	if len(res.Matches) == 0 {
		return []sarifResult{
			{
				RuleID:  "vertguard/identity/clean",
				Level:   sarifLevel(string(res.Classification)),
				Message: sarifMessage{Text: fmt.Sprintf("scan_id=%s classification=%s confidence=%.3f", res.ScanID, res.Classification, res.Confidence)},
			},
		}
	}
	out := make([]sarifResult, 0, len(res.Matches))
	for _, m := range res.Matches {
		msg := fmt.Sprintf("%s — %s (confidence=%.3f)", m.PatternID, m.Description, m.Confidence)
		if m.Detail != "" {
			msg += ": " + m.Detail
		}
		out = append(out, sarifResult{
			RuleID:  m.PatternID,
			Level:   sarifLevel(string(res.Classification)),
			Message: sarifMessage{Text: msg},
		})
	}
	return out
}

func mediaSARIFResults(res *media.Result) []sarifResult {
	level := "note"
	switch res.TrustStatus {
	case media.TrustStatusRevoked, media.TrustStatusUntrusted:
		level = "error"
	case media.TrustStatusUnsigned:
		level = "warning"
	}

	msg := fmt.Sprintf("trust_status=%s has_manifest=%v signature_valid=%v", res.TrustStatus, res.HasManifest, res.SignatureValid)
	if len(res.Errors) > 0 {
		msg += fmt.Sprintf(" errors=%v", res.Errors)
	}

	return []sarifResult{
		{
			RuleID:  "vertguard/media/c2pa",
			Level:   level,
			Message: sarifMessage{Text: msg},
		},
	}
}
