// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSRFAttack_Run_BlocksProductionTarget(t *testing.T) {
	a := NewSSRFAttack()
	_, err := a.Run(context.Background(), "https://api-live.example.com", map[string]any{})
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestSSRFAttack_Run_ConfirmedWhenBodyLeaksMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"instance-id":"i-0123456789","local-ipv4":"169.254.1.1"}`))
	}))
	defer server.Close()

	a := NewSSRFAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints":   []string{"/api/fetch"},
		"param_names": []string{"url"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when response body leaks AWS IMDS-like data")
	}
	if len(result.Evidence) == 0 {
		t.Fatal("expected evidence entries")
	}
	// Every payload attempted for the single endpoint/param combination should
	// yield a "confirmed" entry since the mock server always leaks metadata.
	for _, e := range result.Evidence {
		if !containsAll(e, "SSRF[confirmed]") {
			t.Errorf("expected confirmed SSRF evidence, got %q", e)
		}
	}
}

func TestSSRFAttack_Run_PossibleWhenBodyAcceptedButNoSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	a := NewSSRFAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints":   []string{"/api/fetch"},
		"param_names": []string{"url"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// containsSSRFSignal returns false for this body, so Success should
	// remain false even though the server accepted the payload.
	if result.Success {
		t.Error("expected Success=false when no SSRF signal is present in the body")
	}
	for _, e := range result.Evidence {
		if !containsAll(e, "SSRF[possible]") {
			t.Errorf("expected possible SSRF evidence, got %q", e)
		}
	}
}

func TestSSRFAttack_Run_NonOKIgnored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewSSRFAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints":   []string{"/api/fetch"},
		"param_names": []string{"url"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when server returns 404 for every probe")
	}
	if len(result.Evidence) != 0 {
		t.Errorf("expected no evidence, got %v", result.Evidence)
	}
}

func TestSSRFAttack_Run_StopsOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewSSRFAttack()
	_, err := a.Run(ctx, server.URL, map[string]any{
		"endpoints":   []string{"/api/fetch"},
		"param_names": []string{"url"},
	})
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
}

func TestContainsSSRFSignal(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"aws imds signal", `{"instance-id":"i-1"}`, true},
		{"gcp signal", `{"computeMetadata":true}`, true},
		{"azure signal", `{"subscriptionId":"x"}`, true},
		{"etc passwd signal", "root:x:0:0:root:/root:/bin/bash", true},
		{"memcached signal", "VERSION 1.6.0", true},
		{"no signal", `{"hello":"world"}`, false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsSSRFSignal(tt.body); got != tt.want {
				t.Errorf("containsSSRFSignal(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// containsAll reports whether s contains substr. Kept as a distinct name from
// the standard library to make intent explicit in assertions above.
func containsAll(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return len(substr) == 0
}
