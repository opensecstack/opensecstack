//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReady_DBUp_ReturnsOK is the success-path counterpart to
// TestReady_DBUnreachable_ReturnsServiceUnavailable — proves /readyz reports
// ready when the real test database is reachable. requireDB is shared from
// authorize_test.go (same package, same integration build tag).
func TestReady_DBUp_ReturnsOK(t *testing.T) {
	pool := requireDB(t)
	d := Deps{Pool: pool}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	Ready(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("status field = %q, want ready", body["status"])
	}
}
