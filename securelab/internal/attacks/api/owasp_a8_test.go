// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMisconfigAttack_Run_BlocksProductionTarget(t *testing.T) {
	a := NewMisconfigAttack()
	_, err := a.Run(context.Background(), "https://app_prod.example.com", map[string]any{})
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestMisconfigAttack_Run_DetectsExposedDebugEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/env" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"env":"leaked"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewMisconfigAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when a debug endpoint returns HTTP 200")
	}
	found := false
	for _, e := range result.Evidence {
		if len(e) > 0 && strings.Contains(e, "debug-endpoint") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected debug-endpoint evidence, got %v", result.Evidence)
	}
}

func TestMisconfigAttack_Run_DetectsDefaultCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"fake"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewMisconfigAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when default credentials are accepted")
	}
	found := false
	for _, e := range result.Evidence {
		if strings.Contains(e, "default-creds") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected default-creds evidence, got %v", result.Evidence)
	}
}

func TestMisconfigAttack_Run_DetectsVerboseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/users/not-a-valid-id-99999" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("panic: runtime error: index out of range\n\ngoroutine 1 [running]:\nmain.main()\n\t/home/app/main.go:42"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewMisconfigAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when a stack trace leaks in an error response")
	}
	found := false
	for _, e := range result.Evidence {
		if strings.Contains(e, "verbose-error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected verbose-error evidence, got %v", result.Evidence)
	}
}

func TestMisconfigAttack_Run_DetectsMissingSecurityHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No security headers set at all; every non-matched path 404s.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	a := NewMisconfigAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when required security headers are absent")
	}
	missingHeaderEvidence := 0
	for _, e := range result.Evidence {
		if strings.Contains(e, "missing-header") {
			missingHeaderEvidence++
		}
	}
	if missingHeaderEvidence != len(requiredSecurityHeaders) {
		t.Errorf("expected %d missing-header evidence entries, got %d", len(requiredSecurityHeaders), missingHeaderEvidence)
	}
}

func TestMisconfigAttack_Run_CleanServerReportsNoFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			w.WriteHeader(http.StatusUnauthorized)
			return
		case "/":
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.WriteHeader(http.StatusOK)
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer server.Close()

	a := NewMisconfigAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected Success=false for a fully hardened server, got evidence %v", result.Evidence)
	}
	if len(result.Evidence) != 0 {
		t.Errorf("expected no evidence, got %v", result.Evidence)
	}
}

func TestMisconfigAttack_Run_CustomLoginEndpoint(t *testing.T) {
	var hitPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			hitPath = r.URL.Path
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	a := NewMisconfigAttack()
	_, err := a.Run(context.Background(), server.URL, map[string]any{
		"login_endpoint": "/auth/signin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hitPath != "/auth/signin" {
		t.Errorf("expected login probes to hit /auth/signin, got %q", hitPath)
	}
}

func TestMisconfigAttack_Run_StopsOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewMisconfigAttack()
	_, err := a.Run(ctx, server.URL, map[string]any{})
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
}

func TestVerboseError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"go panic", "panic: runtime error: nil pointer", true},
		{"java exception", "java.lang.NullPointerException at com.foo.Bar", true},
		{"sql error", "SQLSTATE[42000]: syntax error", true},
		{"unix path leak", "open /var/www/html/config.php: no such file", true},
		{"clean body", `{"error":"not found"}`, false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verboseError(tt.body); got != tt.want {
				t.Errorf("verboseError(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
