//go:build bench

package benches

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/google/uuid"
)

// scanRequest mirrors a typical scan creation payload for marshalling
// benchmarks. It intentionally lives here rather than importing the internal
// model so the bench package remains a lightweight, standalone harness.
type scanRequest struct {
	SpecURL string   `json:"spec_url"`
	Target  string   `json:"target"`
	Profile string   `json:"profile,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

// finding mirrors a typical finding payload with all common fields populated.
type finding struct {
	ID          string  `json:"id"`
	ScanID      string  `json:"scan_id"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Path        string  `json:"path"`
	Method      string  `json:"method"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	CVSS        float64 `json:"cvss_score"`
	CreatedAt   string  `json:"created_at"`
}

// BenchmarkValidateTarget measures the cost of parsing and validating a target
// URL, which is the first check performed on every incoming scan request.
func BenchmarkValidateTarget(b *testing.B) {
	b.ReportAllocs()
	const rawURL = "https://api.example.com/v1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, err := url.ParseRequestURI(rawURL)
		if err != nil || u.Host == "" {
			b.Fatalf("unexpected parse error: %v", err)
		}
		_ = u
	}
}

// BenchmarkJSONMarshal_ScanRequest measures the cost of marshalling a typical
// scan creation request to JSON, representing the serialisation path hit on
// every POST /api/v1/scans call.
func BenchmarkJSONMarshal_ScanRequest(b *testing.B) {
	b.ReportAllocs()
	req := scanRequest{
		SpecURL: "https://api.example.com/openapi.json",
		Target:  "https://api.example.com",
		Profile: "owasp-top10",
		Tags:    []string{"ci", "regression"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(req)
		if err != nil {
			b.Fatalf("marshal: %v", err)
		}
		_ = data
	}
}

// BenchmarkJSONMarshal_Finding measures the cost of marshalling a fully
// populated finding, which is the hot path when returning scan results.
func BenchmarkJSONMarshal_Finding(b *testing.B) {
	b.ReportAllocs()
	f := finding{
		ID:          "f1a2b3c4-0000-0000-0000-000000000001",
		ScanID:      "a0000000-0000-0000-0000-000000000001",
		Severity:    "HIGH",
		Title:       "SQL Injection in /users endpoint",
		Description: "The id parameter is concatenated directly into the SQL query without sanitisation.",
		Path:        "/api/v1/users",
		Method:      "GET",
		Evidence:    "id=1' OR '1'='1",
		Remediation: "Use parameterised queries or a prepared statement.",
		CVSS:        8.6,
		CreatedAt:   "2026-03-31T00:00:00Z",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(f)
		if err != nil {
			b.Fatalf("marshal: %v", err)
		}
		_ = data
	}
}

// BenchmarkUUIDGeneration measures the baseline cost of generating a new UUID,
// which is performed for every scan, finding, and audit record created.
func BenchmarkUUIDGeneration(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := uuid.New()
		_ = id
	}
}

// BenchmarkHashChain measures the cost of a single SHA-256 hash computation,
// representing the per-entry cost incurred by the WORM chain integrity step.
func BenchmarkHashChain(b *testing.B) {
	b.ReportAllocs()
	// Simulate a WORM entry payload: previous hash + current record bytes.
	prevHash := make([]byte, 32)
	entry := []byte(`{"id":"abc","event":"scan.created","timestamp":"2026-03-31T00:00:00Z"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(prevHash)
		h.Write(entry)
		prevHash = h.Sum(prevHash[:0])
	}
}
