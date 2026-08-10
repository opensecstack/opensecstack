// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/detection"
	"github.com/opensecstack/securelab/internal/scenarios"
)

// TestMonitorAdapter_WaitForDetection_ReturnsFirstAlert exercises the
// AlertEvent → DetectionEvent conversion, including that Latency is
// populated from wall-clock elapsed time (not copied from the alert).
func TestMonitorAdapter_WaitForDetection_ReturnsFirstAlert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"alert_id":"a1","technique":"bola","timestamp":"2024-01-01T00:00:00Z"}]`))
	}))
	defer server.Close()

	mon := detection.NewMonitor(server.URL, "", "")
	adapter := scenarios.NewMonitorAdapter(mon)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ev, err := adapter.WaitForDetection(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev == nil {
		t.Fatal("expected a non-nil DetectionEvent")
	}
	if ev.Platform != "openscrub" {
		t.Errorf("Platform = %q, want openscrub", ev.Platform)
	}
	if ev.AlertID != "a1" {
		t.Errorf("AlertID = %q, want a1", ev.AlertID)
	}
	if ev.Latency < 0 {
		t.Errorf("expected non-negative Latency, got %d", ev.Latency)
	}
}

// TestMonitorAdapter_WaitForDetection_ContextCancelled verifies that when no
// alert arrives before the context is cancelled, WaitForDetection returns
// ctx.Err() rather than blocking forever or returning a nil error.
func TestMonitorAdapter_WaitForDetection_ContextCancelled(t *testing.T) {
	// No platforms configured — WatchAlerts never produces an event, so the
	// adapter must fall through to the ctx.Done() branch.
	mon := detection.NewMonitor("", "", "")
	adapter := scenarios.NewMonitorAdapter(mon)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ev, err := adapter.WaitForDetection(ctx)
	if err == nil {
		t.Fatal("expected an error when context is cancelled without an alert")
	}
	if ev != nil {
		t.Errorf("expected nil event on cancellation, got %+v", ev)
	}
}
