// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/opensecstack/securelab/internal/db"
)

// Teardown stops and removes the target container and the isolated network
// associated with env. It runs all cleanup steps regardless of individual
// failures, collecting errors so that partial cleanup is always attempted.
//
// The container name is derived from the environment name (securelab-target-<name>).
// The network is identified by env.NetworkID.
func Teardown(ctx context.Context, env *db.Environment) error {
	var errs []error

	if env.Name != "" {
		containerName := "securelab-target-" + env.Name

		// 1. Stop the container (graceful, 5-second timeout).
		if err := dockerStop(ctx, containerName); err != nil {
			errs = append(errs, fmt.Errorf("teardown: stop container %q: %w", containerName, err))
		}

		// 2. Remove the container.
		if err := dockerRm(ctx, containerName); err != nil {
			errs = append(errs, fmt.Errorf("teardown: remove container %q: %w", containerName, err))
		}
	}

	if env.NetworkID != "" {
		// 3. Delete the isolated network.
		if err := DeleteNetwork(ctx, env.NetworkID); err != nil {
			errs = append(errs, fmt.Errorf("teardown: delete network %q: %w", env.NetworkID, err))
		}
	}

	return errors.Join(errs...)
}

// dockerStop sends SIGTERM to the container and waits up to 5 seconds.
func dockerStop(ctx context.Context, containerID string) error {
	cmd := exec.CommandContext(ctx, "docker", "stop", "--time", "5", containerID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker stop: %w (stderr=%s)", err, stderr.String())
	}
	return nil
}

// dockerRm forcibly removes the container (--force handles already-stopped).
func dockerRm(ctx context.Context, containerID string) error {
	cmd := exec.CommandContext(ctx, "docker", "rm", "--force", containerID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker rm: %w (stderr=%s)", err, stderr.String())
	}
	return nil
}
