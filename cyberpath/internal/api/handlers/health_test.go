package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	tests := []struct {
		name       string
		wantStatus int
	}{
		{"alive returns 200", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			rr := httptest.NewRecorder()
			Healthz()(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type = %q, want application/json", ct)
			}
		})
	}
}

func TestReadyzDraining(t *testing.T) {
	Ready.Store(false)
	defer Ready.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	Readyz(nil, nil)(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

// fakeNIS2Checker implements NIS2HealthChecker for tests.
type fakeNIS2Checker struct {
	ok  bool
	err error
}

func (f fakeNIS2Checker) Health(_ context.Context) (bool, error) { return f.ok, f.err }

func TestReadyzWithNIS2Checker(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	Readyz(stubPingerOK{}, fakeNIS2Checker{ok: true})(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	integrations, ok := body["integrations"].(map[string]any)
	if !ok {
		t.Fatalf("missing integrations field: %v", body)
	}
	if integrations["nis2compass"] != "connected" {
		t.Errorf("nis2compass = %v, want connected", integrations["nis2compass"])
	}
}

func TestReadyzWithNIS2Checker_Unreachable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	Readyz(stubPingerOK{}, fakeNIS2Checker{ok: false})(rr, req)
	// nis2compass is best-effort — unreachable must not fail /readyz.
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	integrations, _ := body["integrations"].(map[string]any)
	if integrations["nis2compass"] != "unreachable" {
		t.Errorf("nis2compass = %v, want unreachable", integrations["nis2compass"])
	}
}

type stubPingerOK struct{}

func (stubPingerOK) Ping(context.Context) error { return nil }
