# Docker Lab Setup

This document covers how CyberPath provisions, isolates, and cleans up Docker-based lab environments. The relevant source files are `internal/labs/docker.go`, `internal/labs/orchestrator.go`, `internal/labs/network.go`, and `internal/labs/cleanup.go`.

## Orchestration Overview

The lab lifecycle is managed by `internal/labs/orchestrator.go`. When a user starts a lab:

1. `orchestrator.go` reads the resolved `lab.yaml` for the module.
2. It calls `docker.go:StartLab()` to pull the image (if not cached) and create the container.
3. It calls `network.go:CreateLabNetwork()` to create an isolated bridge network and attach the container.
4. It registers the lab session in the database with status `active`.
5. It schedules a cleanup job via `cleanup.go` for `time_limit_minutes` in the future.

The orchestrator is stateless; all session state is stored in the database. Multiple backend replicas can handle lab operations safely.

## Network Isolation

Each lab session gets its own Docker bridge network, created by `internal/labs/network.go`. The naming convention is `cyberpath-lab-{session_id}`. Network properties:

- No routing between lab networks (learners cannot communicate with each other's containers).
- No default route to the internet (`com.docker.network.bridge.enable_ip_masquerade=false` for strict isolation).
- An internal DNS resolver handles name lookups within the lab network (e.g., a multi-container lab where the target API and a database are both defined in `lab.yaml`).
- The CyberPath backend's lab proxy is attached to the network only long enough to handle a browser terminal connection, then detached.

## Container Images

### Pulling and Caching

Images are pulled via the Docker daemon on the host. Pull happens at lab start time if the image is not already present locally. To pre-cache images for production deployments:

```bash
make lab-images-pull
```

This runs `docker pull` for every image referenced across all `lab.yaml` files found under `content/`.

### Custom Images

Custom images must be pushed to a registry accessible by the CyberPath host. Reference them in `lab.yaml` as `image: registry.example.com/mylab:1.0.0`. The platform does not build images at runtime.

Published images must:
- Declare a non-root `USER`.
- Expose only the ports listed in `lab.yaml`.
- Not include real credentials or secrets.

## Resource Limits

`cpu_limit` and `memory_limit` from `lab.yaml` are passed directly to Docker:

```go
// internal/labs/docker.go
HostConfig: &container.HostConfig{
    NanoCPUs:  cpuLimitToNano(lab.Resources.CPULimit),
    Memory:    memoryLimitToBytes(lab.Resources.MemoryLimit),
}
```

If the container exceeds its memory limit, Docker OOM-kills it. The orchestrator detects the `OOMKilled` state via the Docker event stream and marks the session as `failed` with reason `oom`.

## Lab Cleanup

`internal/labs/cleanup.go` runs the following steps when a lab session expires or is manually terminated:

1. Stop the container (`docker stop` with a 10-second grace period).
2. Remove the container (`docker rm`).
3. Detach and remove the lab network (`docker network rm`).
4. Update the session status to `cleaned` in the database.

Cleanup is triggered by:
- The scheduled cleanup job (at `time_limit_minutes`).
- The user clicking "End Lab" in the UI.
- An operator calling `DELETE /admin/labs/sessions/{id}`.

Orphaned sessions (e.g., from a backend crash) are recovered by a cleanup sweep that runs every 5 minutes and terminates any container whose session has been in `active` state longer than `time_limit_minutes + 10`.

## Docker Socket Requirements

The CyberPath backend requires access to the Docker socket (`/var/run/docker.sock`). This is a privileged capability. Production deployments should:

- Run the CyberPath backend in a dedicated VM or node separate from other workloads.
- Use Docker socket proxies (e.g., Tecnativa socket proxy) to restrict which Docker API calls the backend can make.
- Not expose the Docker socket to lab containers under any circumstances.

## Example: VAmPI and crAPI Lab Setup

### VAmPI (OWASP API Top 10 labs)

```yaml
id: vampi-bola
type: docker
image: erev0s/vampi:latest
ports:
  - container: 5000
    expose: true
resources:
  cpu_limit: "0.25"
  memory_limit: "128m"
environment:
  - name: JWT_SECRET
    value: "supersecret"
```

### crAPI (Broken Function Level Authorization)

```yaml
id: crapi-bfla
type: docker
image: crapi/crapi:latest
ports:
  - container: 8888
    expose: true
  - container: 8025
    expose: true
resources:
  cpu_limit: "0.5"
  memory_limit: "512m"
network:
  isolation: strict
  egress_internet: false
```

crAPI uses a multi-service compose-style setup. At present, the orchestrator supports single-image labs; multi-container labs should be packaged as a single image using a process supervisor (e.g., `s6-overlay`).
