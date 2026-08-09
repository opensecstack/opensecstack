package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
