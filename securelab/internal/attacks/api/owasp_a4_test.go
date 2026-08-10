// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitBypassAttack_Run_BlocksProductionTarget(t *testing.T) {
	a := NewRateLimitBypassAttack()
	_, err := a.Run(context.Background(), "https://svc-prod.example.com", map[string]any{})
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestRateLimitBypassAttack_Run_DetectsMissingRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := NewRateLimitBypassAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"burst":       10,
		"concurrency": 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when server never returns 429")
	}
	if result.Technique != "RateLimitBypass" {
		t.Errorf("Technique = %q, want RateLimitBypass", result.Technique)
	}
}

func TestRateLimitBypassAttack_Run_EffectiveRateLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	a := NewRateLimitBypassAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"burst":       10,
		"concurrency": 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when every request is rate-limited (429)")
	}
}

func TestRateLimitBypassAttack_Run_ConcurrencyCappedForSafety(t *testing.T) {
	// concurrency=500 should be capped to 50 internally; this test just
	// verifies the attack still runs to completion successfully rather than
	// spawning an unbounded number of goroutines.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	a := NewRateLimitBypassAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"burst":       20,
		"concurrency": 500,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("expected exactly one evidence summary line, got %d: %v", len(result.Evidence), result.Evidence)
	}
}

func TestRateLimitBypassAttack_Run_StopsOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewRateLimitBypassAttack()
	_, err := a.Run(ctx, server.URL, map[string]any{"burst": 5})
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
}

func TestGenerateSpoofedIPs(t *testing.T) {
	ips := generateSpoofedIPs(5)
	if len(ips) != 5 {
		t.Fatalf("expected 5 IPs, got %d", len(ips))
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("duplicate IP generated: %q", ip)
		}
		seen[ip] = true
	}
	if ips[0] != "10.0.0.1" {
		t.Errorf("ips[0] = %q, want 10.0.0.1", ips[0])
	}
}
