// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments

import (
	"context"
	"strings"
	"testing"
)

// All tests here use an already-cancelled context so the underlying docker
// process is never actually started (verified: cmd.Run() returns
// "context canceled" before spawning docker), keeping these tests
// deterministic and free of side effects on a real docker daemon.

func TestProvision_NetworkFailureAbortsBeforeContainerStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := NewDockerEnvironment()
	env, err := d.Provision(ctx, "myenv", "alpine:latest")
	if err == nil {
		t.Fatal("expected error when network creation fails")
	}
	if env != nil {
		t.Errorf("expected nil environment on failure, got %+v", env)
	}
	if !strings.Contains(err.Error(), "create network") {
		t.Errorf("expected error to identify the network-creation step, got: %v", err)
	}
}

func TestRunContainer_CommandFailureIsWrapped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	id, err := runContainer(ctx, "securelab-target-x", "alpine:latest", "securelab-x")
	if err == nil {
		t.Fatal("expected error when docker run cannot execute")
	}
	if id != "" {
		t.Errorf("expected empty container ID on failure, got %q", id)
	}
	if !strings.Contains(err.Error(), "alpine:latest") {
		t.Errorf("expected error to mention the image, got: %v", err)
	}
}

func TestContainerIP_CommandFailureIsWrapped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ip, err := containerIP(ctx, "abc123", "securelab-x")
	if err == nil {
		t.Fatal("expected error when docker inspect cannot execute")
	}
	if ip != "" {
		t.Errorf("expected empty IP on failure, got %q", ip)
	}
}
