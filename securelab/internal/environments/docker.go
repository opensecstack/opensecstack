// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/opensecstack/securelab/internal/db"
)

// DockerEnvironment provisions and manages isolated Docker environments
// for SecureLab attack simulation targets.
type DockerEnvironment struct{}

// NewDockerEnvironment returns a DockerEnvironment.
func NewDockerEnvironment() *DockerEnvironment { return &DockerEnvironment{} }

// Provision creates an isolated Docker network and starts the target container
// connected exclusively to that network. The container is not reachable from
// the host network or the internet (--internal network).
//
// Returns an Environment record. The NetworkID field holds the Docker network
// ID; the Name field holds the container name for use with Teardown.
func (d *DockerEnvironment) Provision(ctx context.Context, name, image string) (*db.Environment, error) {
	networkName := "securelab-" + name

	// 1. Create isolated internal network.
	networkID, err := CreateIsolatedNetwork(ctx, networkName)
	if err != nil {
		return nil, fmt.Errorf("docker.Provision: create network: %w", err)
	}

	// 2. Start the target container on the isolated network.
	containerName := "securelab-target-" + name
	containerID, err := runContainer(ctx, containerName, image, networkName)
	if err != nil {
		// Best-effort cleanup of the network we just created.
		_ = DeleteNetwork(ctx, networkID)
		return nil, fmt.Errorf("docker.Provision: start container: %w", err)
	}

	// 3. Determine the container's IP address on the isolated network.
	targetIP, err := containerIP(ctx, containerID, networkName)
	if err != nil {
		// IP detection failure is non-fatal; use container name as fallback.
		targetIP = containerName
	}

	env := &db.Environment{
		// ID is assigned by the DB layer on insert; use containerID as a
		// temporary identifier until the caller persists the record.
		ID:        containerID,
		Name:      name,
		Kind:      "docker",
		NetworkID: networkID,
		TargetURL: "http://" + targetIP,
		Status:    "running",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return env, nil
}

// runContainer starts a Docker container in detached mode on the given network.
// Returns the full container ID.
func runContainer(ctx context.Context, name, image, networkName string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "run",
		"--detach",
		"--name", name,
		"--network", networkName,
		"--label", "securelab.managed=true",
		"--restart", "no",
		image,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker run %q: %w (stderr=%s)", image, err, stderr.String())
	}

	id := strings.TrimSpace(stdout.String())
	if id == "" {
		return "", fmt.Errorf("docker run returned empty container ID for image %q", image)
	}
	return id, nil
}

// containerIP inspects the container to retrieve its IP on the given network.
func containerIP(ctx context.Context, containerID, networkName string) (string, error) {
	format := fmt.Sprintf("{{.NetworkSettings.Networks.%s.IPAddress}}", networkName)
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", format,
		containerID,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker inspect %q: %w (stderr=%s)", containerID, err, stderr.String())
	}

	ip := strings.TrimSpace(stdout.String())
	if ip == "" {
		return "", fmt.Errorf("docker inspect: empty IP for container %q on network %q", containerID, networkName)
	}
	return ip, nil
}
