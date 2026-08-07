// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"strings"
	"testing"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/scenarios"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func validSpec(steps ...scenarios.StepSpec) *scenarios.ScenarioSpec {
	if len(steps) == 0 {
		steps = []scenarios.StepSpec{{Kind: "bola"}}
	}
	return &scenarios.ScenarioSpec{
		Name:     "test-scenario",
		Severity: "high",
		Steps:    steps,
	}
}

func envWithURL(url string) *db.Environment {
	return &db.Environment{TargetURL: url}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestValidate_NilSpec(t *testing.T) {
	err := scenarios.Validate(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil spec, got nil")
	}
}

func TestValidate_EmptyName(t *testing.T) {
	spec := validSpec()
	spec.Name = ""
	err := scenarios.Validate(spec, nil)
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("expected error to mention 'name', got: %s", err)
	}
}

func TestValidate_NoSteps(t *testing.T) {
	spec := validSpec()
	spec.Steps = nil
	err := scenarios.Validate(spec, nil)
	if err == nil {
		t.Fatal("expected error for empty steps, got nil")
	}
	if !strings.Contains(err.Error(), "steps") {
		t.Errorf("expected error to mention 'steps', got: %s", err)
	}
}

func TestValidate_UnknownStepKind(t *testing.T) {
	spec := validSpec(scenarios.StepSpec{Kind: "totally_unknown_kind"})
	err := scenarios.Validate(spec, nil)
	if err == nil {
		t.Fatal("expected error for unknown step kind, got nil")
	}
	if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("expected error to mention 'unknown kind', got: %s", err)
	}
}

func TestValidate_ValidSpec(t *testing.T) {
	spec := validSpec(scenarios.StepSpec{Kind: "bola"})
	err := scenarios.Validate(spec, nil)
	if err != nil {
		t.Fatalf("expected no error for valid spec, got: %s", err)
	}
}

func TestValidate_ProductionURL_ProdSuffix(t *testing.T) {
	spec := validSpec()
	env := envWithURL("https://api.prod/v1")
	err := scenarios.Validate(spec, env)
	if err == nil {
		t.Fatal("expected error for production URL, got nil")
	}
}

func TestValidate_ProductionURL_ProductionSubdomain(t *testing.T) {
	spec := validSpec()
	env := envWithURL("https://production.example.com")
	err := scenarios.Validate(spec, env)
	if err == nil {
		t.Fatal("expected error for production.example.com, got nil")
	}
}

func TestValidate_SafeURL(t *testing.T) {
	spec := validSpec()
	env := envWithURL("http://192.168.100.10:8080")
	err := scenarios.Validate(spec, env)
	if err != nil {
		t.Fatalf("expected no error for safe URL, got: %s", err)
	}
}

func TestValidate_AllValidStepKinds(t *testing.T) {
	for kind := range scenarios.ValidStepKinds {
		kind := kind // capture
		t.Run(kind, func(t *testing.T) {
			spec := validSpec(scenarios.StepSpec{Kind: kind})
			err := scenarios.Validate(spec, nil)
			if err != nil {
				t.Errorf("kind %q: expected no error, got: %s", kind, err)
			}
		})
	}
}
