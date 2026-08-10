// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments_test

import (
	"context"
	"strings"
	"testing"

	"github.com/opensecstack/securelab/internal/environments"
)

// These tests use an already-cancelled context so exec.CommandContext never
// actually spawns the docker process (Go returns "context canceled" from
// cmd.Run() before starting it), giving deterministic, side-effect-free
// coverage of the error-wrapping paths without touching a real docker daemon.

func TestCreateIsolatedNetwork_CommandFailureIsWrapped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	id, err := environments.CreateIsolatedNetwork(ctx, "securelab-test-net")
	if err == nil {
		t.Fatal("expected error when docker command cannot run")
	}
	if id != "" {
		t.Errorf("expected empty network ID on error, got %q", id)
	}
	if !strings.Contains(err.Error(), "securelab-test-net") {
		t.Errorf("expected error to mention the network name, got: %v", err)
	}
}

func TestDeleteNetwork_CommandFailureIsWrapped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := environments.DeleteNetwork(ctx, "net-abc123")
	if err == nil {
		t.Fatal("expected error when docker command cannot run")
	}
	if !strings.Contains(err.Error(), "net-abc123") {
		t.Errorf("expected error to mention the network ID, got: %v", err)
	}
}
