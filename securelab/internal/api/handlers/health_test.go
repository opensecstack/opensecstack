// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/api/handlers"
)

func TestHealthHandler_Degraded(t *testing.T) {
	// The pool is unreachable, so Ping fails and the handler must report a
	// degraded status with HTTP 503.
	pool := unreachablePool(t)
	startTime := time.Now().Add(-5 * time.Second)
	h := handlers.HealthHandler(pool, startTime)

	rr := do(h, newGetRequest("/health", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when DB is unreachable, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content type, got %q", ct)
	}

	var body struct {
		Status        string `json:"status"`
		DB            bool   `json:"db"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		Version       string `json:"version"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body.Status != "degraded" {
		t.Fatalf("expected status %q, got %q", "degraded", body.Status)
	}
	if body.DB {
		t.Fatal("expected db=false when the pool is unreachable")
	}
	if body.UptimeSeconds < 5 {
		t.Fatalf("expected uptime_seconds >= 5, got %d", body.UptimeSeconds)
	}
	if body.Version == "" {
		t.Fatal("expected a non-empty version string")
	}
}
