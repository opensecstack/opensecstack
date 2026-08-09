// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBOLAAttack_Run_MissingJWT(t *testing.T) {
	a := NewBOLAAttack()
	_, err := a.Run(context.Background(), "http://127.0.0.1:1", map[string]any{})
	if err == nil {
		t.Fatal("expected error when jwt param is missing")
	}
}

func TestBOLAAttack_Run_BlocksProductionTarget(t *testing.T) {
	a := NewBOLAAttack()
	_, err := a.Run(context.Background(), "https://api.production.example.com", map[string]any{"jwt": "x"})
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestBOLAAttack_Run_DetectsUnauthorizedAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only ID "3" is "vulnerable" and returns 200; everything else 404.
		if r.URL.Path == "/api/users/3" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":3,"secret":"leaked"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewBOLAAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"jwt":      "low-priv-jwt",
		"start_id": 1,
		"end_id":   5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when one ID returns HTTP 200")
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("expected exactly 1 evidence entry, got %d: %v", len(result.Evidence), result.Evidence)
	}
	if result.Technique != "BOLA" {
		t.Errorf("Technique = %q, want BOLA", result.Technique)
	}
}

func TestBOLAAttack_Run_NoVulnerabilityFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	a := NewBOLAAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"jwt": "x", "start_id": 1, "end_id": 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when every probe returns 403")
	}
}

func TestBOLAAttack_Run_UUIDModeAddsProbes(t *testing.T) {
	var gotPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewBOLAAttack()
	_, err := a.Run(context.Background(), server.URL, map[string]any{
		"jwt": "x", "start_id": 1, "end_id": 1, "uuid_mode": true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 numeric ID + 4 well-known UUIDs = 5 requests.
	if len(gotPaths) != 5 {
		t.Errorf("expected 5 probe requests (1 numeric + 4 uuid), got %d: %v", len(gotPaths), gotPaths)
	}
}

func TestIntParam(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		def    int
		want   int
	}{
		{"absent key uses default", map[string]any{}, 7, 7},
		{"int value used directly", map[string]any{"k": 42}, 7, 42},
		{"float64 value converted", map[string]any{"k": float64(9)}, 7, 9},
		{"wrong type falls back to default", map[string]any{"k": "not-a-number"}, 7, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intParam(tt.params, "k", tt.def)
			if got != tt.want {
				t.Errorf("intParam() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short string = %q, want unchanged", got)
	}
	got := truncate("hello world", 5)
	if got != "hello…" {
		t.Errorf("truncate long string = %q, want %q", got, "hello…")
	}
}

func TestBOLAAttack_Run_StopsOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	a := NewBOLAAttack()
	_, err := a.Run(ctx, server.URL, map[string]any{"jwt": "x", "start_id": 1, "end_id": 1})
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
}
