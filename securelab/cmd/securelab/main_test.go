// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

const validScenarioYAML = `
name: test-scenario
severity: low
steps:
  - kind: bola
`

const invalidStepScenarioYAML = `
name: bad-scenario
severity: low
steps:
  - kind: not_a_real_kind
`

const emptyStepsScenarioYAML = `
name: no-steps
severity: low
`

// ---------------------------------------------------------------------------
// resolveDSN
// ---------------------------------------------------------------------------

func TestResolveDSN_ExplicitWins(t *testing.T) {
	t.Setenv("SECURELAB_DB_URL", "postgres://env-value")
	if got := resolveDSN("postgres://explicit"); got != "postgres://explicit" {
		t.Errorf("resolveDSN = %q, want explicit value", got)
	}
}

func TestResolveDSN_FallsBackToEnv(t *testing.T) {
	t.Setenv("SECURELAB_DB_URL", "postgres://env-value")
	if got := resolveDSN(""); got != "postgres://env-value" {
		t.Errorf("resolveDSN = %q, want env value", got)
	}
}

func TestResolveDSN_EmptyWhenNeitherSet(t *testing.T) {
	t.Setenv("SECURELAB_DB_URL", "")
	if got := resolveDSN(""); got != "" {
		t.Errorf("resolveDSN = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// cmdValidate
// ---------------------------------------------------------------------------

func TestCmdValidate_NoArgs(t *testing.T) {
	if err := cmdValidate(nil); err == nil {
		t.Fatal("expected error when no scenario path given")
	}
}

func TestCmdValidate_FileNotFound(t *testing.T) {
	if err := cmdValidate([]string{filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCmdValidate_InvalidYAMLSyntax(t *testing.T) {
	p := writeTempFile(t, "bad.yaml", "name: [unterminated")
	if err := cmdValidate([]string{p}); err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestCmdValidate_ValidationFails(t *testing.T) {
	p := writeTempFile(t, "invalid-step.yaml", invalidStepScenarioYAML)
	err := cmdValidate([]string{p})
	if err == nil {
		t.Fatal("expected validation error for unknown step kind")
	}
	if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("error = %v, want message mentioning unknown kind", err)
	}
}

func TestCmdValidate_Success(t *testing.T) {
	p := writeTempFile(t, "valid.yaml", validScenarioYAML)
	if err := cmdValidate([]string{p}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// cmdRun
// ---------------------------------------------------------------------------

func TestCmdRun_FlagParseError(t *testing.T) {
	log := zap.NewNop()
	if err := cmdRun([]string{"--not-a-real-flag"}, log); err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestCmdRun_MissingScenarioArg(t *testing.T) {
	log := zap.NewNop()
	err := cmdRun([]string{"--target", "http://127.0.0.1:8080"}, log)
	if err == nil {
		t.Fatal("expected error when no scenario file arg is given")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Errorf("error = %v, want usage message", err)
	}
}

func TestCmdRun_MissingTarget(t *testing.T) {
	log := zap.NewNop()
	p := writeTempFile(t, "valid.yaml", validScenarioYAML)
	err := cmdRun([]string{p}, log)
	if err == nil {
		t.Fatal("expected error when --target is missing")
	}
	if !strings.Contains(err.Error(), "--target is required") {
		t.Errorf("error = %v, want '--target is required'", err)
	}
}

func TestCmdRun_ScenarioFileNotFound(t *testing.T) {
	log := zap.NewNop()
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	err := cmdRun([]string{"--target", "http://127.0.0.1:8080", missing}, log)
	if err == nil {
		t.Fatal("expected error for missing scenario file")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error = %v, want message about reading the file", err)
	}
}

func TestCmdRun_InvalidYAML(t *testing.T) {
	log := zap.NewNop()
	p := writeTempFile(t, "bad.yaml", "name: [unterminated")
	err := cmdRun([]string{"--target", "http://127.0.0.1:8080", p}, log)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !strings.Contains(err.Error(), "parse yaml") {
		t.Errorf("error = %v, want message about parsing yaml", err)
	}
}

func TestCmdRun_ScenarioValidationFails(t *testing.T) {
	log := zap.NewNop()
	p := writeTempFile(t, "empty-steps.yaml", emptyStepsScenarioYAML)
	err := cmdRun([]string{"--target", "http://127.0.0.1:8080", p}, log)
	if err == nil {
		t.Fatal("expected validation error for scenario with no steps")
	}
	if !strings.Contains(err.Error(), "validation:") {
		t.Errorf("error = %v, want message prefixed with 'validation:'", err)
	}
}

func TestCmdRun_MissingDSN(t *testing.T) {
	t.Setenv("SECURELAB_DB_URL", "")
	log := zap.NewNop()
	p := writeTempFile(t, "valid.yaml", validScenarioYAML)
	err := cmdRun([]string{"--target", "http://127.0.0.1:8080", p}, log)
	if err == nil {
		t.Fatal("expected error when neither --db nor SECURELAB_DB_URL is set")
	}
	if !strings.Contains(err.Error(), "--db or SECURELAB_DB_URL is required") {
		t.Errorf("error = %v, want message about missing DSN", err)
	}
}

// ---------------------------------------------------------------------------
// cmdList
// ---------------------------------------------------------------------------

func TestCmdList_FlagParseError(t *testing.T) {
	if err := cmdList([]string{"--not-a-real-flag"}); err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestCmdList_MissingDSN(t *testing.T) {
	t.Setenv("SECURELAB_DB_URL", "")
	err := cmdList(nil)
	if err == nil {
		t.Fatal("expected error when neither --db nor SECURELAB_DB_URL is set")
	}
	if !strings.Contains(err.Error(), "--db or SECURELAB_DB_URL is required") {
		t.Errorf("error = %v, want message about missing DSN", err)
	}
}

// ---------------------------------------------------------------------------
// printUsage / noopMonitor
// ---------------------------------------------------------------------------

func TestPrintUsage_DoesNotPanic(t *testing.T) {
	printUsage()
}

func TestNoopMonitor_WaitForDetection_ReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := &noopMonitor{}
	event, err := m.WaitForDetection(ctx)
	if event != nil {
		t.Errorf("event = %v, want nil", event)
	}
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}
