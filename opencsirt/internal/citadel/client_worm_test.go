package citadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

// TestClient_Submit_HitsWormEmit proves the citadel client (used by the
// outbox watcher for audit-only events: incident create, triage-escalation)
// now delivers to the route CITADEL actually exposes — POST
// /api/v1/worm/emit — instead of the nonexistent /api/v1/events that
// silently swallowed every event before this fix.
func TestClient_Submit_HitsWormEmit(t *testing.T) {
	var gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"worm_entry_id": "11111111-1111-1111-1111-111111111111",
			"chain_hash":    "abc123",
			"prev_hash":     "def456",
			"sequence_num":  1,
		})
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("test-hmac-secret-0123456789")}, "opencsirt-1", "opencsirt-test", false, zerolog.Nop())

	outcome, err := c.Submit(context.Background(), "opencsirt.incident_opened", "incident-open-xyz",
		map[string]any{"incident_id": "xyz", "severity": "high"})
	if err != nil {
		t.Fatalf("Submit: unexpected error: %v", err)
	}
	if outcome != SubmitDelivered {
		t.Fatalf("outcome = %v, want SubmitDelivered", outcome)
	}

	if gotPath != "/api/v1/worm/emit" {
		t.Errorf("request hit path %q, want /api/v1/worm/emit", gotPath)
	}
	if gotBody["source"] != "opencsirt" {
		t.Errorf("source = %v, want \"opencsirt\"", gotBody["source"])
	}
	if gotBody["event_type"] != "opencsirt.incident_opened" {
		t.Errorf("event_type = %v, want \"opencsirt.incident_opened\"", gotBody["event_type"])
	}
	if gotBody["project_id"] != "opencsirt-test" {
		t.Errorf("project_id = %v, want \"opencsirt-test\"", gotBody["project_id"])
	}
	payload, ok := gotBody["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing or wrong type: %v", gotBody["payload"])
	}
	if payload["incident_id"] != "xyz" {
		t.Errorf("payload.incident_id = %v, want \"xyz\"", payload["incident_id"])
	}
}

// TestClient_Submit_DefaultsProjectID proves New() falls back to
// "opencsirt" when no project ID is supplied, mirroring NewFromConfig's
// default so operators who haven't set OPENCSIRT_CITADEL_PROJECT_ID still
// get a sensible, non-empty project_id on every WORM entry.
func TestClient_Submit_DefaultsProjectID(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"worm_entry_id": "1", "sequence_num": 1})
	}))
	defer srv.Close()

	c := New(srv.URL, [][]byte{[]byte("test-hmac-secret-0123456789")}, "opencsirt-1", "", false, zerolog.Nop())
	if _, err := c.Submit(context.Background(), "opencsirt.incident_opened", "evt-1", map[string]any{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotBody["project_id"] != "opencsirt" {
		t.Errorf("project_id = %v, want default \"opencsirt\"", gotBody["project_id"])
	}
}
