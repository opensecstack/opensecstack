package citadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEmit_HitsWORMEmitEndpoint verifies the bug fix: Emit used to POST to
// /api/v1/events, a route that has never existed on CITADEL (see
// citadel/internal/api/server.go's route table), so every call was silently
// failing. It must now POST to /api/v1/worm/emit with the shape CITADEL's
// WORM handler expects (citadel/internal/api/handlers/worm.go's emitRequest).
func TestEmit_HitsWORMEmitEndpoint(t *testing.T) {
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
			"chain_hash":    "abc",
			"prev_hash":     "def",
			"sequence_num":  1,
		})
	}))
	defer srv.Close()

	c := New(srv.URL, []string{"test-secret"}, "community-1", false)

	err := c.Emit(context.Background(), Event{
		Kind:      "community.post.published",
		NodeID:    "community-0",
		Timestamp: time.Now(),
		Payload:   map[string]any{"post_id": "p1", "author": "alice"},
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	if gotPath != "/api/v1/worm/emit" {
		t.Fatalf("expected path /api/v1/worm/emit, got %q", gotPath)
	}
	if gotBody["source"] != "community" {
		t.Errorf("expected source=community, got %v", gotBody["source"])
	}
	if gotBody["event_type"] != "community.post.published" {
		t.Errorf("expected event_type=community.post.published, got %v", gotBody["event_type"])
	}
	if gotBody["project_id"] != "community-0" {
		t.Errorf("expected project_id=community-0, got %v", gotBody["project_id"])
	}
	payload, ok := gotBody["payload"].(map[string]any)
	if !ok {
		t.Fatalf("expected payload object, got %T: %v", gotBody["payload"], gotBody["payload"])
	}
	if payload["post_id"] != "p1" {
		t.Errorf("expected payload.post_id=p1, got %v", payload["post_id"])
	}
}

// TestEmit_DryRunDoesNotCallNetwork ensures the dry-run short-circuit still
// works after the endpoint fix (no HTTP call at all).
func TestEmit_DryRunDoesNotCallNetwork(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, "community-1", true) // dryRun = true

	if err := c.Emit(context.Background(), Event{Kind: "community.post.published"}); err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}
	if called {
		t.Error("expected no HTTP call in dry-run mode")
	}
}

// TestEmit_NonOKStatusReturnsError verifies a non-2xx/3xx response from
// /api/v1/worm/emit surfaces as an error rather than being swallowed.
func TestEmit_NonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, "community-1", false)

	err := c.Emit(context.Background(), Event{Kind: "community.post.published"})
	if err == nil {
		t.Fatal("expected an error for a 500 response, got nil")
	}
}
