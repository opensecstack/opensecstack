package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opensecstack/vertguard/internal/identity"
	"github.com/opensecstack/vertguard/internal/media"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
)

func promptResult() prompt.ScanResult {
	return prompt.ScanResult{
		ScanID:         "scan-1",
		Classification: prompt.ClassificationBlocked,
		Confidence:     0.91,
		Matches: []prompt.Match{
			{PatternID: "PI-001", Category: "injection", Description: "ignore previous instructions", Confidence: 0.91},
		},
	}
}

func TestGenerate_JSON(t *testing.T) {
	g := NewGenerator()
	r := Report{ScanID: "scan-1", ScanType: "prompt", Result: promptResult(), GeneratedAt: "2026-01-01T00:00:00Z"}

	var buf bytes.Buffer
	if err := g.Generate(context.Background(), &buf, r, FormatJSON); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.ScanID != "scan-1" {
		t.Errorf("scan_id = %q, want %q", decoded.ScanID, "scan-1")
	}
	if decoded.ScanType != "prompt" {
		t.Errorf("scan_type = %q, want %q", decoded.ScanType, "prompt")
	}
}

func TestGenerate_UnsupportedFormat(t *testing.T) {
	g := NewGenerator()
	r := Report{ScanID: "scan-1", ScanType: "prompt", Result: promptResult()}

	var buf bytes.Buffer
	err := g.Generate(context.Background(), &buf, r, Format("yaml"))
	if err == nil {
		t.Fatal("Generate() error = nil, want error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error = %v, want it to mention unsupported format", err)
	}
	if buf.Len() != 0 {
		t.Errorf("buf.Len() = %d, want 0 (nothing written on unsupported format)", buf.Len())
	}
}

func TestGenerate_SARIF(t *testing.T) {
	g := NewGenerator()
	r := Report{ScanID: "scan-1", ScanType: "prompt", Result: promptResult()}

	var buf bytes.Buffer
	if err := g.Generate(context.Background(), &buf, r, FormatSARIF); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "VertGuard" {
		t.Errorf("driver name = %q, want VertGuard", log.Runs[0].Tool.Driver.Name)
	}
	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(log.Runs[0].Results))
	}
	if log.Runs[0].Results[0].RuleID != "PI-001" {
		t.Errorf("ruleId = %q, want PI-001", log.Runs[0].Results[0].RuleID)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("level = %q, want error (BLOCKED classification)", log.Runs[0].Results[0].Level)
	}
}

func TestGenerate_HTML_RendererFailure(t *testing.T) {
	// Point the renderer at a binary that cannot possibly exist so the
	// subprocess invocation fails deterministically without depending
	// on python being installed in the test environment.
	g := &Generator{htmlRenderer: &HTMLRenderer{PythonBin: "vertguard-definitely-not-a-real-binary"}}
	r := Report{ScanID: "scan-1", ScanType: "prompt", Result: promptResult()}

	var buf bytes.Buffer
	err := g.Generate(context.Background(), &buf, r, FormatHTML)
	if err == nil {
		t.Fatal("Generate() error = nil, want error when python binary is missing")
	}
	if !strings.Contains(err.Error(), "reporter: python render") {
		t.Errorf("error = %v, want it to be wrapped as python render failure", err)
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		classification string
		want           string
	}{
		{"BLOCKED", "error"},
		{"SUSPICIOUS", "warning"},
		{"CLEAN", "note"},
		{"UNKNOWN_VALUE", "note"},
	}
	for _, tt := range tests {
		if got := sarifLevel(tt.classification); got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.classification, got, tt.want)
		}
	}
}

func TestExtractSARIFResults_PromptCleanNoMatches(t *testing.T) {
	res := prompt.ScanResult{ScanID: "s1", Classification: prompt.ClassificationClean, Confidence: 0.1}
	results := extractSARIFResults(Report{ScanType: "prompt", Result: res})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].RuleID != "vertguard/prompt/clean" {
		t.Errorf("ruleId = %q, want vertguard/prompt/clean", results[0].RuleID)
	}
	if results[0].Level != "note" {
		t.Errorf("level = %q, want note", results[0].Level)
	}
}

func TestExtractSARIFResults_PromptPointer(t *testing.T) {
	res := promptResult()
	results := extractSARIFResults(Report{ScanType: "prompt", Result: &res})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].RuleID != "PI-001" {
		t.Errorf("ruleId = %q, want PI-001", results[0].RuleID)
	}
}

func TestExtractSARIFResults_Phishing(t *testing.T) {
	res := phishing.ScanResult{
		ScanID:         "s2",
		Classification: phishing.ClassificationSuspicious,
		Confidence:     0.5,
		Matches: []phishing.Match{
			{PatternID: "PH-001", Category: "url", Description: "lookalike domain", Confidence: 0.5},
		},
	}
	results := extractSARIFResults(Report{ScanType: "phishing", Result: res})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].RuleID != "PH-001" {
		t.Errorf("ruleId = %q, want PH-001", results[0].RuleID)
	}
	if results[0].Level != "warning" {
		t.Errorf("level = %q, want warning (SUSPICIOUS)", results[0].Level)
	}
}

func TestExtractSARIFResults_Identity(t *testing.T) {
	res := identity.ScanResult{
		ScanID:         "s3",
		Classification: identity.ClassificationBlocked,
		Confidence:     0.9,
		Matches: []identity.Match{
			{PatternID: "ID-001", Category: "impersonation", Description: "claims to be admin", Confidence: 0.9, Detail: "extra context"},
		},
	}
	results := extractSARIFResults(Report{ScanType: "identity", Result: res})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if !strings.Contains(results[0].Message.Text, "extra context") {
		t.Errorf("message = %q, want it to include the Detail field", results[0].Message.Text)
	}
}

func TestExtractSARIFResults_Media(t *testing.T) {
	tests := []struct {
		name       string
		trustState string
		wantLevel  string
	}{
		{"trusted", media.TrustStatusTrusted, "note"},
		{"unsigned", media.TrustStatusUnsigned, "warning"},
		{"untrusted", media.TrustStatusUntrusted, "error"},
		{"revoked", media.TrustStatusRevoked, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := media.Result{TrustStatus: tt.trustState, HasManifest: true, SignatureValid: true}
			results := extractSARIFResults(Report{ScanType: "media", Result: res})
			if len(results) != 1 {
				t.Fatalf("len(results) = %d, want 1", len(results))
			}
			if results[0].Level != tt.wantLevel {
				t.Errorf("level = %q, want %q", results[0].Level, tt.wantLevel)
			}
			if results[0].RuleID != "vertguard/media/c2pa" {
				t.Errorf("ruleId = %q, want vertguard/media/c2pa", results[0].RuleID)
			}
		})
	}
}

func TestExtractSARIFResults_UnknownType(t *testing.T) {
	results := extractSARIFResults(Report{ScanType: "mystery", Result: "not a known type"})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].RuleID != "vertguard/unknown" {
		t.Errorf("ruleId = %q, want vertguard/unknown", results[0].RuleID)
	}
	if !strings.Contains(results[0].Message.Text, "mystery") {
		t.Errorf("message = %q, want it to include scan_type", results[0].Message.Text)
	}
}
