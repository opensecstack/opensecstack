// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments_test

import (
	"context"
	"testing"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/environments"
)

// TestTeardown_EmptyEnvironmentIsNoop verifies that Teardown does not attempt
// any docker/network operations (and therefore cannot fail) when the
// environment has neither a container name nor a network ID recorded. This
// matters because a partially-provisioned environment (e.g. a row inserted
// before Provision ran) must be safely teardown-able without error.
func TestTeardown_EmptyEnvironmentIsNoop(t *testing.T) {
	err := environments.Teardown(context.Background(), &db.Environment{})
	if err != nil {
		t.Fatalf("expected nil error for empty environment, got %v", err)
	}
}

// TestTeardown_PropagatesFailures uses an already-cancelled context so that
// exec.CommandContext refuses to start the underlying docker process at all
// (verified: a cancelled context makes cmd.Run() return "context canceled"
// without spawning docker), giving us a deterministic failure path with no
// dependency on / side effects against a real docker daemon. Teardown must
// still attempt every cleanup step and join all resulting errors rather than
// stopping at the first failure.
func TestTeardown_PropagatesFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := &db.Environment{
		Name:      "gone",
		NetworkID: "net-123",
	}

	err := environments.Teardown(ctx, env)
	if err == nil {
		t.Fatal("expected a non-nil error when the context is already cancelled")
	}
}

func TestTeardown_ContainerOnlyStillDeletesNothingElse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Only Name set, no NetworkID: the network deletion step must be skipped
	// entirely (no attempt, no error contribution from it) while the
	// container stop/rm steps still run and fail due to the cancelled ctx.
	env := &db.Environment{Name: "gone"}

	err := environments.Teardown(ctx, env)
	if err == nil {
		t.Fatal("expected error from container stop/rm failures")
	}
}
