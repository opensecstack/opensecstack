// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/scenarios"
)

func TestLoadFromYAML_FullSpec(t *testing.T) {
	yaml := `
name: phishing-sim
description: A test scenario
mitre_technique_ids: ["T1190", "T1078"]
tags: ["api", "owasp"]
severity: high
timeout: 5m
steps:
  - kind: bola
    params:
      start_id: 1
      end_id: 10
  - kind: ssrf
`
	spec, err := scenarios.LoadFromYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Name != "phishing-sim" {
		t.Errorf("Name = %q, want phishing-sim", spec.Name)
	}
	if spec.Severity != "high" {
		t.Errorf("Severity = %q, want high", spec.Severity)
	}
	if spec.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", spec.Timeout)
	}
	if len(spec.MitreTechniqueIDs) != 2 || spec.MitreTechniqueIDs[0] != "T1190" {
		t.Errorf("MitreTechniqueIDs = %v, want [T1190 T1078]", spec.MitreTechniqueIDs)
	}
	if len(spec.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(spec.Steps))
	}
	if spec.Steps[0].Kind != "bola" {
		t.Errorf("Steps[0].Kind = %q, want bola", spec.Steps[0].Kind)
	}
	startID, ok := spec.Steps[0].Params["start_id"]
	if !ok || startID != 1 {
		t.Errorf("Steps[0].Params[start_id] = %v, want 1", startID)
	}
}

func TestLoadFromYAML_MinimalSpecDefaultsNilSlicesToEmpty(t *testing.T) {
	spec, err := scenarios.LoadFromYAML([]byte("name: minimal\nseverity: low\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.MitreTechniqueIDs == nil {
		t.Error("expected MitreTechniqueIDs to default to empty slice, got nil")
	}
	if spec.Tags == nil {
		t.Error("expected Tags to default to empty slice, got nil")
	}
	if spec.Steps == nil {
		t.Error("expected Steps to default to empty slice, got nil")
	}
	if spec.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0 (unset)", spec.Timeout)
	}
}

func TestLoadFromYAML_InvalidYAMLSyntax(t *testing.T) {
	_, err := scenarios.LoadFromYAML([]byte("name: [unterminated"))
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestLoadFromYAML_InvalidTimeoutDuration(t *testing.T) {
	_, err := scenarios.LoadFromYAML([]byte("name: x\nseverity: low\ntimeout: not-a-duration\n"))
	if err == nil {
		t.Fatal("expected error for unparsable timeout duration")
	}
}

func TestLoadFromYAML_EmptyDocument(t *testing.T) {
	spec, err := scenarios.LoadFromYAML([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty document: %v", err)
	}
	if spec.Name != "" {
		t.Errorf("expected empty Name for empty document, got %q", spec.Name)
	}
	if spec.Steps == nil || len(spec.Steps) != 0 {
		t.Errorf("expected empty (non-nil) Steps, got %v", spec.Steps)
	}
}
