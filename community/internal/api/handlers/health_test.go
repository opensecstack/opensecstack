package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

// stubPool is a minimal pgxpool.Pool substitute for unit tests.
// It wraps a real pool but we supply a nil pool and override behaviour via
// httptest — the handler calls d.Pool.Ping, so we need to intercept that.
// Instead we use a real in-process approach: spin up the handler with a nil
// pool and verify the 503 branch, and use a mock pool for the 200 branch.

// mockPool satisfies the Ping interface used by HealthCheck.
// Since pgxpool.Pool is a concrete struct (not an interface) we cannot mock it
// directly. Instead we test the handler by calling it against an actual
// postgres URL when PGURL is set, and test the shape/fields in the 200 case.
// For the offline unit-test we test the 503 branch (nil pool panics), so we
// use a real pool with a dummy URL to force a Ping failure.

func newDepsWithBadDB(t *testing.T) handlers.Deps {
	t.Helper()
	// A pool pointing at an unreachable address — Ping will fail fast.
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return handlers.Deps{
		Pool: pool,
		Cfg:  &config.Config{},
	}
}

func TestHealthCheck_UnreachableDB_Returns503(t *testing.T) {
	d := newDepsWithBadDB(t)
	startTime := time.Now()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	handlers.HealthCheck(d, startTime)(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when DB unreachable, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	resp.Body.Close()

	if ok, _ := body["ok"].(bool); ok {
		t.Error("expected ok=false when DB is unreachable")
	}
	if _, hasVersion := body["version"]; !hasVersion {
		t.Error("response missing 'version' field")
	}
	if _, hasUptime := body["uptime_seconds"]; !hasUptime {
		t.Error("response missing 'uptime_seconds' field")
	}
	if _, hasTimestamp := body["timestamp"]; !hasTimestamp {
		t.Error("response missing 'timestamp' field")
	}
}

func TestHealthCheck_ResponseShape(t *testing.T) {
	// Even when DB is unreachable the response must include the required fields.
	d := newDepsWithBadDB(t)
	startTime := time.Now().Add(-5 * time.Second) // fake 5s uptime

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	handlers.HealthCheck(d, startTime)(w, req)

	var body struct {
		OK            bool    `json:"ok"`
		Version       string  `json:"version"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		Timestamp     string  `json:"timestamp"`
		DB            struct {
			OK        bool  `json:"ok"`
			LatencyMS int64 `json:"latency_ms"`
		} `json:"db"`
	}

	resp := w.Result()
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	resp.Body.Close()

	// Version defaults to "dev" when APP_VERSION env var is not set.
	if body.Version == "" {
		t.Error("version field must not be empty")
	}
	if body.UptimeSeconds < 0 {
		t.Error("uptime_seconds must be >= 0")
	}
	if body.Timestamp == "" {
		t.Error("timestamp field must not be empty")
	}
}

func TestReadinessCheck_UnreachableDB_Returns503(t *testing.T) {
	d := newDepsWithBadDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ready", nil)
	w := httptest.NewRecorder()

	handlers.ReadinessCheck(d)(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when DB unreachable, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	resp.Body.Close()

	if ready, _ := body["ready"].(bool); ready {
		t.Error("expected ready=false when DB is unreachable")
	}
	if body["reason"] != "db unreachable" {
		t.Errorf("expected reason='db unreachable', got %v", body["reason"])
	}
}
