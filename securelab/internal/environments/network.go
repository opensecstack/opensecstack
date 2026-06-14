// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package environments manages isolated Docker (and Wasm) test environments
// for SecureLab attack simulations.
package environments

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CreateIsolatedNetwork creates an internal Docker bridge network that has no
// routing to the host or external internet (--internal flag).
// Returns the network ID assigned by Docker.
func CreateIsolatedNetwork(ctx context.Context, name string) (string, error) {
	// --internal: restrict the network to container-to-container communication only.
	// --driver bridge: explicit bridge driver for predictable behaviour.
	cmd := exec.CommandContext(ctx, "docker", "network", "create",
		"--driver", "bridge",
		"--internal",
		"--label", "securelab.managed=true",
		name,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("environments: create network %q: %w (stderr=%s)", name, err, stderr.String())
	}

	networkID := strings.TrimSpace(stdout.String())
	if networkID == "" {
		return "", fmt.Errorf("environments: docker network create returned empty ID for %q", name)
	}
	return networkID, nil
}

// DeleteNetwork removes a Docker network by its ID.
func DeleteNetwork(ctx context.Context, networkID string) error {
	cmd := exec.CommandContext(ctx, "docker", "network", "rm", networkID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("environments: delete network %q: %w (stderr=%s)", networkID, err, stderr.String())
	}
	return nil
}
