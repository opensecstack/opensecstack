// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPFlood_Run_BlocksPublicTarget(t *testing.T) {
	h := NewHTTPFlood()
	_, err := h.Run(context.Background(), "93.184.216.34", "80", nil)
	if err == nil {
		t.Fatal("expected error for public IP target")
	}
}

func TestHTTPFlood_Run_SendsRequestsToLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	h := NewHTTPFlood()
	result, err := h.Run(context.Background(), host, port, map[string]any{
		"requests":    20,
		"concurrency": 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true after sending requests to a live server")
	}
	if result.Technique != "HTTPFlood" {
		t.Errorf("Technique = %q, want HTTPFlood", result.Technique)
	}
	if len(result.Evidence) != 1 {
		t.Errorf("expected 1 evidence summary line, got %d", len(result.Evidence))
	}
}

func TestHTTPFlood_Run_DurationMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())

	h := NewHTTPFlood()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := h.Run(ctx, host, port, map[string]any{
		"duration":    "200ms",
		"concurrency": 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true in duration mode")
	}
}

func TestPercentiles_EmptyInput(t *testing.T) {
	p50, p95, p99 := percentiles(nil)
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("expected all zero for empty input, got p50=%v p95=%v p99=%v", p50, p95, p99)
	}
}

func TestPercentiles_SortedResults(t *testing.T) {
	durations := []time.Duration{
		100 * time.Millisecond,
		50 * time.Millisecond,
		200 * time.Millisecond,
		10 * time.Millisecond,
	}
	p50, p95, p99 := percentiles(durations)
	// idx(pct) = sorted[int(float64(len-1)*pct)] ; len=4 -> len-1=3
	// p50: int(3*0.5)=1 -> sorted[1] = 50ms
	// p95: int(3*0.95)=2 -> sorted[2] = 100ms
	// p99: int(3*0.99)=2 -> sorted[2] = 100ms
	if p50 != 50*time.Millisecond {
		t.Errorf("p50 = %v, want 50ms", p50)
	}
	if p95 != 100*time.Millisecond {
		t.Errorf("p95 = %v, want 100ms", p95)
	}
	if p99 != 100*time.Millisecond {
		t.Errorf("p99 = %v, want 100ms", p99)
	}
}
