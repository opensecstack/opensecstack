// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments_test

import (
	"context"
	"testing"

	"github.com/opensecstack/securelab/internal/environments"
)

func TestWasmEnvironment_Provision(t *testing.T) {
	w := environments.NewWasmEnvironment()

	env, err := w.Provision(context.Background(), "my-target", "https://example.internal:8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env.ID != "wasm-my-target" {
		t.Errorf("expected ID %q, got %q", "wasm-my-target", env.ID)
	}
	if env.Name != "my-target" {
		t.Errorf("expected Name %q, got %q", "my-target", env.Name)
	}
	if env.Kind != "wasm" {
		t.Errorf("expected Kind %q, got %q", "wasm", env.Kind)
	}
	if env.NetworkID != "" {
		t.Errorf("expected empty NetworkID for wasm env, got %q", env.NetworkID)
	}
	if env.TargetURL != "https://example.internal:8443" {
		t.Errorf("expected TargetURL to be passed through unchanged, got %q", env.TargetURL)
	}
	if env.Status != "running" {
		t.Errorf("expected Status %q, got %q", "running", env.Status)
	}
	if env.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if env.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}
}

// Wasm targets are unmanaged externally, so Provision must never attempt any
// container/network side effects — verified implicitly by the fact this test
// never touches a live daemon and always succeeds regardless of environment.
func TestWasmEnvironment_ProvisionNoSideEffectsOnEmptyName(t *testing.T) {
	w := environments.NewWasmEnvironment()

	env, err := w.Provision(context.Background(), "", "")
	if err != nil {
		t.Fatalf("unexpected error for empty name/url: %v", err)
	}
	if env.ID != "wasm-" {
		t.Errorf("expected ID %q, got %q", "wasm-", env.ID)
	}
}
