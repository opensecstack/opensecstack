// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package citadel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// emitRequestWire mirrors citadel/internal/api/handlers/worm.go's emitRequest
// struct so the test can decode what the connector actually sent.
type emitRequestWire struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id"`
	Payload   json.RawMessage `json:"payload"`
}

func TestEmitRunCompleted_PostsToWormEmit(t *testing.T) {
	var (
		gotPath   string
		gotMethod string
		gotBody   emitRequestWire
		gotSig    string
		gotSrcHdr string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotSig = r.Header.Get("X-CITADEL-Signature")
		gotSrcHdr = r.Header.Get("X-CITADEL-Source")

		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"worm_entry_id":"00000000-0000-0000-0000-000000000000","chain_hash":"x","prev_hash":"y","sequence_num":1}`))
	}))
	defer server.Close()

	c := NewConnector(server.URL, "test-secret")

	if err := c.EmitRunCompleted(t.Context(), "run-123", "phishing-sim", "completed", 0.75); err != nil {
		t.Fatalf("EmitRunCompleted returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/worm/emit" {
		t.Errorf("path = %q, want /api/v1/worm/emit", gotPath)
	}
	if gotSig == "" {
		t.Error("expected X-CITADEL-Signature header to be set")
	}
	if gotSrcHdr != "securelab" {
		t.Errorf("X-CITADEL-Source = %q, want securelab", gotSrcHdr)
	}

	if gotBody.Source != "securelab" {
		t.Errorf("body.source = %q, want securelab", gotBody.Source)
	}
	if gotBody.EventType != "securelab.run_completed" {
		t.Errorf("body.event_type = %q, want securelab.run_completed", gotBody.EventType)
	}
	if len(gotBody.Payload) == 0 {
		t.Error("expected non-empty payload")
	}

	var payload runCompletedEvent
	if err := json.Unmarshal(gotBody.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.RunID != "run-123" {
		t.Errorf("payload.run_id = %q, want run-123", payload.RunID)
	}
	if payload.ScenarioName != "phishing-sim" {
		t.Errorf("payload.scenario_name = %q, want phishing-sim", payload.ScenarioName)
	}
	if payload.Status != "completed" {
		t.Errorf("payload.status = %q, want completed", payload.Status)
	}
	if payload.DetectionRate != 0.75 {
		t.Errorf("payload.detection_rate = %v, want 0.75", payload.DetectionRate)
	}
}

func TestEmitRunCompleted_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewConnector(server.URL, "test-secret")

	if err := c.EmitRunCompleted(t.Context(), "run-456", "phishing-sim", "failed", 0); err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}
}
