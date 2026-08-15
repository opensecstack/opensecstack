// Package docker wraps the Docker Engine API for CyberPath lab provisioning.
// Each lab session gets its own container; resource limits are applied at
// creation time and containers are removed explicitly via StopContainer.
package docker

import (
	"context"
	"encoding/json"
	"io"
	"time"

	dockerclient "github.com/docker/docker/client"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"

	"github.com/opensecstack/cyberpath/internal/db"
)

const (
	memoryLimit = 256 * 1024 * 1024 // 256 MB
	cpuQuota    = 50000             // 0.5 CPU (in microseconds per 100 ms period)
	stopTimeout = 10                // seconds
)

// Provisioner manages Docker containers for lab sessions.
type Provisioner struct {
	client *dockerclient.Client
}

// New creates a Provisioner connected to the Docker daemon. It uses the
// DOCKER_HOST environment variable when set, falling back to the platform
// default socket (unix:///var/run/docker.sock on Linux/macOS, npipe on Windows).
func New() (*Provisioner, error) {
	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	return &Provisioner{client: cli}, nil
}

// StartContainer pulls the image if not already present, then creates and
// starts a container for the given lab definition. Returns the container ID.
//
// Constraints applied:
//   - memory: 256 MB
//   - CPU quota: 50000 µs / 100 ms period (≈ 0.5 CPU)
//   - network: "none" unless def.EgressWhitelist is non-empty, then "bridge"
//   - auto-remove: false (container must be explicitly removed after the session)
//   - labels: cyberpath.session_id, cyberpath.lab_id
func (p *Provisioner) StartContainer(ctx context.Context, def *db.LabDefinition, sessionID string) (string, error) {
	// Pull image if not present locally.
	if err := p.ensureImage(ctx, def.Image); err != nil {
		return "", err
	}

	// Choose network mode: isolated by default, bridge when egress is configured.
	netMode := networkModeFor(def.EgressWhitelist)

	// Build the container command. Use the definition's EntryCommand if set,
	// otherwise fall back to /bin/sh.
	cmd := containerCommand(def.EntryCommand)

	timeout := stopTimeout
	cfg := &container.Config{
		Image:       def.Image,
		Cmd:         cmd,
		Tty:         true,
		OpenStdin:   true,
		StdinOnce:   false,
		StopTimeout: &timeout,
		Labels:      containerLabels(sessionID, def.ID),
	}

	hostCfg := &container.HostConfig{
		NetworkMode: netMode,
		AutoRemove:  false,
		Resources: container.Resources{
			Memory:   memoryLimit,
			CPUQuota: cpuQuota,
		},
	}

	resp, err := p.client.ContainerCreate(ctx, cfg, hostCfg, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		return "", err
	}

	if err := p.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		// Clean up the created-but-not-started container.
		_ = p.client.ContainerRemove(context.Background(), resp.ID, container.RemoveOptions{Force: true})
		return "", err
	}

	return resp.ID, nil
}

// StopContainer stops and removes the container identified by containerID.
// A 10-second grace period is given before a forced kill.
func (p *Provisioner) StopContainer(ctx context.Context, containerID string) error {
	timeout := stopTimeout
	stopErr := p.client.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	if stopErr != nil && dockerclient.IsErrNotFound(stopErr) {
		// Container already gone (e.g. a repeated call after a prior
		// StopContainer already removed it) — not a real failure.
		stopErr = nil
	}

	// Always attempt removal, even if stop returned an error (e.g. container
	// already exited). Ignore "not found" so idempotent calls are safe.
	rmErr := p.client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	if rmErr != nil && !dockerclient.IsErrNotFound(rmErr) {
		return rmErr
	}

	return stopErr
}

// ExecStream creates an exec session on containerID that runs /bin/sh with a
// TTY and stdin attached, then returns the hijacked connection suitable for
// piping to a WebSocket terminal relay.
func (p *Provisioner) ExecStream(ctx context.Context, containerID string) (dockertypes.HijackedResponse, error) {
	execID, err := p.client.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          []string{"/bin/sh"},
		Tty:          true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return dockertypes.HijackedResponse{}, err
	}

	return p.client.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{
		Tty: true,
	})
}

// networkModeFor returns the Docker network mode a lab container should be
// created with: isolated ("none") by default, "bridge" when the lab
// definition configures a non-empty egress whitelist. Treats a JSON "null"
// or empty-array whitelist the same as no whitelist at all.
func networkModeFor(egressWhitelist json.RawMessage) container.NetworkMode {
	trimmed := string(egressWhitelist)
	if len(trimmed) > 0 && trimmed != "null" && trimmed != "[]" {
		return container.NetworkMode("bridge")
	}
	return container.NetworkMode("none")
}

// containerCommand returns the shell command a lab container should run:
// the definition's EntryCommand executed via `/bin/sh -c` when set,
// otherwise a bare `/bin/sh` for an interactive session.
func containerCommand(entryCommand string) []string {
	if entryCommand != "" {
		return []string{"/bin/sh", "-c", entryCommand}
	}
	return []string{"/bin/sh"}
}

// containerLabels returns the Docker labels applied to every lab container,
// used to identify and later clean up containers by session and lab ID.
func containerLabels(sessionID, labID string) map[string]string {
	return map[string]string{
		"cyberpath.session_id": sessionID,
		"cyberpath.lab_id":     labID,
	}
}

// ensureImage pulls the image if it is not available locally. It discards
// the pull progress output but propagates any error.
func (p *Provisioner) ensureImage(ctx context.Context, imageName string) error {
	// Check local cache first to avoid a round-trip on every start.
	_, err := p.client.ImageInspect(ctx, imageName)
	if err == nil {
		return nil // already present
	}
	if !dockerclient.IsErrNotFound(err) {
		return err
	}

	// Pull with a reasonable timeout so a missing image doesn't block forever.
	pullCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	rc, err := p.client.ImagePull(pullCtx, imageName, image.PullOptions{})
	if err != nil {
		return err
	}
	defer rc.Close()
	_, _ = io.Copy(io.Discard, rc) // drain to completion
	return nil
}
