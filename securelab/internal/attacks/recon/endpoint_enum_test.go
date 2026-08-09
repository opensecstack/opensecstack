// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEndpointEnumerator_Run_BlocksPublicTarget(t *testing.T) {
	e := NewEndpointEnumerator()
	_, err := e.Run(context.Background(), "http://1.1.1.1", nil)
	if err == nil {
		t.Fatal("expected error for public target")
	}
}

func TestEndpointEnumerator_Run_DiscoversNonNotFoundPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	e := NewEndpointEnumerator()
	result, err := e.Run(context.Background(), server.URL, map[string]any{"concurrency": 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when endpoints are discovered")
	}
	if len(result.Endpoints) != 2 {
		t.Fatalf("expected 2 discovered endpoints (/health,/admin), got %d: %+v", len(result.Endpoints), result.Endpoints)
	}
}

func TestEndpointEnumerator_Run_AllNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	e := NewEndpointEnumerator()
	result, err := e.Run(context.Background(), server.URL, map[string]any{"concurrency": 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when every path 404s")
	}
}

func TestEndpointEnumerator_Run_ExtraPaths(t *testing.T) {
	var seenCustom bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/my-custom-secret-path" {
			seenCustom = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	e := NewEndpointEnumerator()
	_, err := e.Run(context.Background(), server.URL, map[string]any{
		"concurrency":  5,
		"extra_paths":  []string{"/my-custom-secret-path"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !seenCustom {
		t.Error("expected extra_paths entry to be probed")
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://127.0.0.1:8080/x?y=1", "127.0.0.1"},
		{"http://host.internal", "host.internal"},
		{"no-scheme-host", "no-scheme-host"},
	}
	for _, tt := range tests {
		if got := extractHost(tt.in); got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
