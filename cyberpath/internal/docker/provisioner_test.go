package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ---------------------------------------------------------------------------
// networkModeFor
// ---------------------------------------------------------------------------

func TestNetworkModeFor(t *testing.T) {
	tests := []struct {
		name string
		in   json.RawMessage
		want container.NetworkMode
	}{
		{"nil whitelist", nil, container.NetworkMode("none")},
		{"empty whitelist", json.RawMessage(""), container.NetworkMode("none")},
		{"JSON null", json.RawMessage("null"), container.NetworkMode("none")},
		{"empty array", json.RawMessage("[]"), container.NetworkMode("none")},
		{"single entry", json.RawMessage(`["example.com"]`), container.NetworkMode("bridge")},
		{"multiple entries", json.RawMessage(`["example.com","cdn.example.com"]`), container.NetworkMode("bridge")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := networkModeFor(tt.in)
			if got != tt.want {
				t.Errorf("networkModeFor(%q) = %q, want %q", string(tt.in), got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containerCommand
// ---------------------------------------------------------------------------

func TestContainerCommand(t *testing.T) {
	tests := []struct {
		name         string
		entryCommand string
		want         []string
	}{
		{"no entry command falls back to bare shell", "", []string{"/bin/sh"}},
		{"entry command wrapped in sh -c", "echo hello", []string{"/bin/sh", "-c", "echo hello"}},
		{"entry command with pipes preserved verbatim", "cat /etc/os-release | grep NAME", []string{"/bin/sh", "-c", "cat /etc/os-release | grep NAME"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containerCommand(tt.entryCommand)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("containerCommand(%q) = %v, want %v", tt.entryCommand, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containerLabels
// ---------------------------------------------------------------------------

func TestContainerLabels(t *testing.T) {
	got := containerLabels("session-123", "lab-abc")
	want := map[string]string{
		"cyberpath.session_id": "session-123",
		"cyberpath.lab_id":     "lab-abc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("containerLabels() = %v, want %v", got, want)
	}
}

func TestContainerLabels_EmptyInputsStillProduceBothKeys(t *testing.T) {
	got := containerLabels("", "")
	if _, ok := got["cyberpath.session_id"]; !ok {
		t.Error("expected cyberpath.session_id key to be present even when empty")
	}
	if _, ok := got["cyberpath.lab_id"]; !ok {
		t.Error("expected cyberpath.lab_id key to be present even when empty")
	}
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

// TestNew_BuildsClientWithoutADaemonConnection proves New() succeeds purely
// from local configuration (DOCKER_HOST / platform default socket path) —
// the Docker SDK client is constructed lazily and does not dial the daemon
// until the first API call, so this must succeed even in environments with
// no Docker daemon running.
func TestNew_BuildsClientWithoutADaemonConnection(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if p == nil {
		t.Fatal("New() returned a nil *Provisioner with a nil error")
	}
	if p.client == nil {
		t.Error("New() returned a Provisioner with a nil underlying client")
	}
}

// ---------------------------------------------------------------------------
// Integration: real Docker daemon (skipped when unavailable)
// ---------------------------------------------------------------------------

// requireDockerDaemon skips the test unless a real Docker daemon is
// reachable, so this suite still passes in CI/sandbox environments without
// Docker Desktop or a daemon socket.
func requireDockerDaemon(t *testing.T) *Provisioner {
	t.Helper()
	p, err := New()
	if err != nil {
		t.Skipf("Docker client unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.client.Ping(ctx); err != nil {
		t.Skipf("Docker daemon unreachable, skipping integration test: %v", err)
	}
	return p
}

// TestStartStopContainer_Integration provisions a trivial container against
// a real Docker daemon and tears it down, exercising StartContainer and
// StopContainer end-to-end. It is gated behind requireDockerDaemon so it
// never blocks the suite in environments without Docker running.
func TestStartStopContainer_Integration(t *testing.T) {
	p := requireDockerDaemon(t)

	def := &db.LabDefinition{
		ID:           "test-lab",
		Image:        "alpine:latest",
		EntryCommand: "",
	}
	sessionID := fmt.Sprintf("test-session-%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerID, err := p.StartContainer(ctx, def, sessionID)
	if err != nil {
		t.Fatalf("StartContainer() error = %v", err)
	}
	if containerID == "" {
		t.Fatal("StartContainer() returned an empty container ID")
	}

	if err := p.StopContainer(context.Background(), containerID); err != nil {
		t.Fatalf("StopContainer() error = %v", err)
	}

	// Idempotent: stopping an already-removed container must not error.
	if err := p.StopContainer(context.Background(), containerID); err != nil {
		t.Errorf("StopContainer() on already-removed container error = %v, want nil (idempotent)", err)
	}
}

// TestExecStream_Integration attaches an exec session to a real running
// container and verifies a hijacked connection is returned, then cleans up.
func TestExecStream_Integration(t *testing.T) {
	p := requireDockerDaemon(t)

	def := &db.LabDefinition{ID: "test-lab-exec", Image: "alpine:latest"}
	sessionID := fmt.Sprintf("test-exec-session-%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerID, err := p.StartContainer(ctx, def, sessionID)
	if err != nil {
		t.Fatalf("StartContainer() error = %v", err)
	}
	defer func() { _ = p.StopContainer(context.Background(), containerID) }()

	hijacked, err := p.ExecStream(ctx, containerID)
	if err != nil {
		t.Fatalf("ExecStream() error = %v", err)
	}
	defer hijacked.Close()
	if hijacked.Conn == nil {
		t.Error("ExecStream() returned a HijackedResponse with a nil Conn")
	}
}

// TestStartContainer_InvalidImageReferenceErrors proves StartContainer
// surfaces the underlying Docker error (via ensureImage's ImageInspect
// call) for a malformed image reference, without attempting a network
// pull — ImageInspect on an invalid reference fails with an
// "invalid reference format" error, not a not-found error, so
// ensureImage must return it immediately rather than falling through to
// ImagePull.
func TestStartContainer_InvalidImageReferenceErrors(t *testing.T) {
	p := requireDockerDaemon(t)

	def := &db.LabDefinition{ID: "test-lab-bad-image", Image: "INVALID::not-a-valid-ref::"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := p.StartContainer(ctx, def, "test-session-bad-image")
	if err == nil {
		t.Fatal("StartContainer() with an invalid image reference: expected an error, got nil")
	}
}
