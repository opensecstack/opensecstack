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

func TestMassAssignmentAttack_Run_BlocksProductionTarget(t *testing.T) {
	a := NewMassAssignmentAttack()
	_, err := a.Run(context.Background(), "https://api.production.example.com", map[string]any{})
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestMassAssignmentAttack_Run_DetectsReflectedFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Echo back one of the injected privileged fields.
		_, _ = w.Write([]byte(`{"name":"attacker","role":"admin"}`))
	}))
	defer server.Close()

	a := NewMassAssignmentAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints": []string{"/api/profile"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when server reflects a privileged field")
	}
	if result.Technique != "MassAssignment" {
		t.Errorf("Technique = %q, want MassAssignment", result.Technique)
	}
	found := false
	for _, e := range result.Evidence {
		if strings.Contains(e, "reflected extra fields") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected evidence describing reflected fields, got %v", result.Evidence)
	}
}

func TestMassAssignmentAttack_Run_AcceptedWithoutReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	a := NewMassAssignmentAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints": []string{"/api/profile"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No reflected fields, so Success must remain false even though the
	// request was accepted (200) — only reflection is flagged as Success.
	if result.Success {
		t.Error("expected Success=false when extra fields are not reflected")
	}
	if len(result.Evidence) == 0 {
		t.Error("expected evidence entry for accepted-but-unclear response")
	}
}

func TestMassAssignmentAttack_Run_NonSuccessStatusIgnored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	a := NewMassAssignmentAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints": []string{"/api/profile"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when server rejects every request")
	}
	if len(result.Evidence) != 0 {
		t.Errorf("expected no evidence, got %v", result.Evidence)
	}
}

func TestMassAssignmentAttack_Run_StopsOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewMassAssignmentAttack()
	_, err := a.Run(ctx, server.URL, map[string]any{"endpoints": []string{"/api/profile"}})
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
}

func TestReflectedFields(t *testing.T) {
	got := reflectedFields([]byte(`{"role":"admin","name":"x"}`))
	if len(got) != 1 || got[0] != "role" {
		t.Errorf("reflectedFields = %v, want [role]", got)
	}

	if got := reflectedFields([]byte(`{"name":"x"}`)); got != nil {
		t.Errorf("expected nil for no matching fields, got %v", got)
	}

	if got := reflectedFields([]byte(`not json`)); got != nil {
		t.Errorf("expected nil for invalid JSON, got %v", got)
	}
}
