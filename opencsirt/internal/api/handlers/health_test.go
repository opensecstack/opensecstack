package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// unreachableHealthPool returns a pgxpool.Pool configured against a
// syntactically valid but unreachable address (port 1 on loopback).
// pgxpool.NewWithConfig never dials eagerly, so construction always
// succeeds; Ping then fails fast with a connection-refused error. This
// exercises dbPing's non-nil-pool branch (previously uncovered) without a
// live Postgres.
func unreachableHealthPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://user:pass@127.0.0.1:1/db")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestHealth_Get_NoPoolNoAdvisory(t *testing.T) {
	h := &Health{StartedAt: time.Now().Add(-5 * time.Second)}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["db"] != false {
		t.Errorf("db = %v, want false (nil pool)", body["db"])
	}
	if body["advisory_service"] != true {
		t.Errorf("advisory_service = %v, want true (no probe configured)", body["advisory_service"])
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if up, ok := body["uptime_seconds"].(float64); !ok || up < 5 {
		t.Errorf("uptime_seconds = %v, want >= 5", body["uptime_seconds"])
	}
}

func TestHealth_Get_AdvisoryProbeFails(t *testing.T) {
	h := &Health{
		StartedAt: time.Now(),
		Advisory: func(ctx context.Context) error {
			return errors.New("advisory down")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["advisory_service"] != false {
		t.Errorf("advisory_service = %v, want false when probe errors", body["advisory_service"])
	}
}

func TestHealth_Get_AdvisoryProbeSucceeds(t *testing.T) {
	h := &Health{
		StartedAt: time.Now(),
		Advisory: func(ctx context.Context) error {
			return nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["advisory_service"] != true {
		t.Errorf("advisory_service = %v, want true when probe succeeds", body["advisory_service"])
	}
}

func TestHealth_DBPing_NilPool(t *testing.T) {
	h := &Health{}
	if h.dbPing(context.Background()) {
		t.Fatal("dbPing must return false when Pool is nil")
	}
}

func TestHealth_DBPing_UnreachablePoolReturnsFalse(t *testing.T) {
	h := &Health{Pool: unreachableHealthPool(t)}
	if h.dbPing(context.Background()) {
		t.Fatal("dbPing must return false when the pool cannot be reached")
	}
}

func TestHealth_Get_UnreachablePoolReportsDBFalse(t *testing.T) {
	h := &Health{Pool: unreachableHealthPool(t), StartedAt: time.Now()}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["db"] != false {
		t.Errorf("db = %v, want false when the pool is unreachable", body["db"])
	}
}
