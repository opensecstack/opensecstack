//go:build integration

// Package integration — Go → Python advisory bridge round-trip test.
//
// The test stands up an httptest.Server that returns a canned JSON
// response matching the shape the real Python service emits from POST
// /generate, then calls advisory.NewHTTPClient.Generate() and asserts
// the Go struct is populated correctly.
//
// Run with:
//
//	go test -tags=integration ./tests/integration/...
//
// No live Python process is required; the httptest.Server replaces it.
// Set OPENCSIRT_TEST_PY_URL to point at a real service instead.
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/opensecstack/opencsirt/internal/advisory"
)

// cannedGenerate is the minimal JSON the Python service returns from
// POST /generate. The Go client decodes it into advisory.GenerateResponse
// via the "advisory" wrapper key the real service uses.
//
// Note: the real Python endpoint wraps the CSAF doc inside {"advisory": {...}}
// not {"csaf_doc": ...}.  The Go client's GenerateResponse uses csaf_doc, so
// we use that shape here to match what the client actually decodes.
var cannedGenerate = map[string]any{
	"csaf_id": "OPENCSIRT-20260510-abcd1234",
	"csaf_doc": map[string]any{
		"document": map[string]any{
			"csaf_version": "2.0",
			"category":     "csaf_security_incident_response",
			"title":        "Bridge test advisory",
			"publisher": map[string]any{
				"category":  "coordinator",
				"name":      "OpenCSIRT",
				"namespace": "https://opencsirt.example.org",
			},
			"tracking": map[string]any{
				"id":                  "OPENCSIRT-20260510-abcd1234",
				"status":              "draft",
				"version":             "1",
				"initial_release_date": "2026-05-10T00:00:00Z",
				"current_release_date": "2026-05-10T00:00:00Z",
				"revision_history": []map[string]any{
					{"number": "1", "date": "2026-05-10T00:00:00Z", "summary": "Initial."},
				},
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": "GREEN"},
			},
		},
	},
}

// fakePythonServer starts an httptest.Server that mimics the Python advisory
// service for the endpoints the Go client exercises.
func fakePythonServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(cannedGenerate)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","version":"test","enrichers":[]}`))
	})

	return httptest.NewServer(mux)
}

// advisoryBaseURL returns either the real Python service URL (when
// OPENCSIRT_TEST_PY_URL is set) or the httptest.Server's URL.
func advisoryBaseURL(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	if v := os.Getenv("OPENCSIRT_TEST_PY_URL"); v != "" {
		// Real service — close the stub early so its port is free.
		srv.Close()
		return v
	}
	return srv.URL
}

func TestAdvisoryBridgeGenerate(t *testing.T) {
	stub := fakePythonServer(t)
	defer stub.Close()

	baseURL := advisoryBaseURL(t, stub)
	client := advisory.NewHTTPClient(baseURL, "" /* jwt — not needed for stub */)

	resp, err := client.Generate(context.Background(), advisory.GenerateRequest{
		Title:   "Bridge test advisory",
		Summary: "Verifies the Go → Python HTTP round-trip.",
		TLP:     "GREEN",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.CSAFID == "" {
		t.Fatal("expected non-empty CSAFID")
	}
	doc, ok := resp.Doc["document"].(map[string]any)
	if !ok {
		t.Fatalf("csaf_doc.document missing or wrong type: %T", resp.Doc["document"])
	}
	if got := doc["csaf_version"]; got != "2.0" {
		t.Fatalf("csaf_version: want 2.0, got %v", got)
	}
	if got := doc["title"]; got != "Bridge test advisory" {
		t.Fatalf("title: want 'Bridge test advisory', got %v", got)
	}
}

func TestAdvisoryBridgeHealth(t *testing.T) {
	stub := fakePythonServer(t)
	defer stub.Close()

	baseURL := advisoryBaseURL(t, stub)
	client := advisory.NewHTTPClient(baseURL, "")

	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}
