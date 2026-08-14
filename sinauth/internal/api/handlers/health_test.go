package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHealth_AlwaysReportsOK(t *testing.T) {
	d := Deps{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	Health(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want ok", body["status"])
	}
	if body["version"] == "" {
		t.Errorf("version field is empty")
	}
}

// TestReady_DBUnreachable_ReturnsServiceUnavailable proves /readyz actually
// checks database connectivity rather than always reporting healthy — a pool
// pointed at a port nothing is listening on must fail the Ping and produce
// 503, not 200. This does not require the real test database.
func TestReady_DBUnreachable_ReturnsServiceUnavailable(t *testing.T) {
	// Port 1 is a reserved/unlikely-to-be-listening port; pgxpool.New is lazy
	// (it does not dial), so this succeeds and only Ping (inside Ready) fails.
	pool, err := pgxpool.New(context.Background(), "postgres://nouser@127.0.0.1:1/nodb?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	d := Deps{Pool: pool}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	Ready(d)(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["status"] != "not ready" {
		t.Errorf("status field = %q, want %q", body["status"], "not ready")
	}
}
