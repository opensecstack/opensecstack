package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/db"
)

// unreachableDB returns a *db.DB backed by a lazily-connecting pool aimed
// at a port that actively refuses connections, so Ping against it fails
// fast with a real connection error instead of hanging.
func unreachableDB(t *testing.T) *db.DB {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return &db.DB{Pool: pool}
}

func TestHealth_ServeHTTP_NoDB_ReportsOK(t *testing.T) {
	h := NewHealth(zerolog.Nop(), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/health", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want %q", resp["status"], "ok")
	}
	// db is nil, so no "db" key should be reported (only checked when db != nil).
	if _, ok := resp["db"]; ok {
		t.Errorf("expected no \"db\" key when db is nil, got %q", resp["db"])
	}
	if resp["version"] == "" {
		t.Error("expected non-empty version field")
	}
}

// TestHealth_ServeHTTP_DBUnreachable_ReportsDegraded confirms the handler
// reports a 503 "degraded" status (not a false "ok") when the database is
// configured but unreachable — a health check that reports "ok" during a
// real DB outage would hide the outage from monitoring/load balancers.
func TestHealth_ServeHTTP_DBUnreachable_ReportsDegraded(t *testing.T) {
	h := NewHealth(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/health", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "degraded" {
		t.Errorf("status = %q, want %q", resp["status"], "degraded")
	}
	if resp["db"] != "unreachable" {
		t.Errorf("db = %q, want %q", resp["db"], "unreachable")
	}
}

func TestHealth_ServeHTTP_ContentType(t *testing.T) {
	h := NewHealth(zerolog.Nop(), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/health", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if ct := rw.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
