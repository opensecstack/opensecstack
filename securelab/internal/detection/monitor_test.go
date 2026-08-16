// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package detection_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/detection"
)

func TestMonitor_WatchAlerts_ForwardsMatchingTechnique(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"alert_id":"a1","technique":"bola","severity":"high","timestamp":"2024-01-01T00:00:00Z"}]`))
	}))
	defer server.Close()

	m := detection.NewMonitor(server.URL, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch := m.WatchAlerts(ctx, "run-1", []string{"bola"})

	select {
	case ev := <-ch:
		if ev.Technique != "bola" {
			t.Errorf("Technique = %q, want bola", ev.Technique)
		}
		if ev.Platform != "openscrub" {
			t.Errorf("Platform = %q, want openscrub", ev.Platform)
		}
		if ev.AlertID != "a1" {
			t.Errorf("AlertID = %q, want a1", ev.AlertID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for alert event")
	}
	cancel()
}

func TestMonitor_WatchAlerts_FiltersNonMatchingTechnique(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"alert_id":"a1","technique":"unrelated_technique","timestamp":"2024-01-01T00:00:00Z"}]`))
	}))
	defer server.Close()

	m := detection.NewMonitor(server.URL, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	ch := m.WatchAlerts(ctx, "run-1", []string{"bola"})

	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("expected no matching event, got %+v", ev)
		}
		// channel closed on ctx done — expected.
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

func TestMonitor_WatchAlerts_EnvelopeFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alerts":[{"alert_id":"a2","technique":"ssrf","timestamp":"2024-01-01T00:00:00Z"}]}`))
	}))
	defer server.Close()

	m := detection.NewMonitor("", server.URL, "")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch := m.WatchAlerts(ctx, "run-1", []string{"ssrf"})

	select {
	case ev := <-ch:
		if ev.AlertID != "a2" || ev.Platform != "apiguard" {
			t.Errorf("got %+v, want alert_id=a2 platform=apiguard", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for envelope-format alert")
	}
}

// TestMonitor_WatchAlerts_NilTechniqueFilterForwardsEverything is a
// regression test for a production bug: passing a nil/empty
// expectedTechniques (as MonitorAdapter.WaitForDetection intentionally does,
// documented as "no run-ID or technique filter") must forward every alert
// regardless of its Technique field. The original implementation only
// forwarded events whose Technique field was itself empty, silently
// dropping every alert that actually names a technique (e.g. "bola") when
// no filter was requested — which meant the executor's detection-confirmed
// signal would never fire for realistic alerts in production.
func TestMonitor_WatchAlerts_NilTechniqueFilterForwardsEverything(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"alert_id":"a1","technique":"bola","severity":"high","timestamp":"2024-01-01T00:00:00Z"}]`))
	}))
	defer server.Close()

	m := detection.NewMonitor(server.URL, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No technique filter (nil), mirroring MonitorAdapter's "accept any
	// alert" call pattern.
	ch := m.WatchAlerts(ctx, "run-1", nil)

	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("expected an alert event, got closed channel")
		}
		if ev.Technique != "bola" {
			t.Errorf("Technique = %q, want bola", ev.Technique)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for alert with nil technique filter — technique-named alerts must still be forwarded when no filter is set")
	}
}

func TestMonitor_WatchAlerts_ClosesOnContextCancel(t *testing.T) {
	m := detection.NewMonitor("", "", "") // no platforms configured — nothing to poll
	ctx, cancel := context.WithCancel(context.Background())

	ch := m.WatchAlerts(ctx, "run-1", nil)
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to be closed with no value")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for channel to close after cancel")
	}
}
