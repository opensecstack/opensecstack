# ADR-002: Support both Docker and Wasm lab environments with Docker as primary

## Status
Accepted

## Context
CyberPath labs require isolated execution environments where students can interact with vulnerable applications, run exploits, and experiment safely without affecting other users or the host system. Four isolation strategies were evaluated:

- **Virtual machines**: strong isolation and full OS support, but provisioning time (30-90 seconds) and resource overhead make them impractical for a per-student, per-lab model.
- **Remote cloud environments**: offloads resource management but introduces latency, requires persistent cloud credentials, and creates a hard cost dependency that conflicts with the goal of self-hostable deployment.
- **Wasm sandboxes (PyramidOS)**: near-instant startup, runs in-process, and requires no elevated host privileges. However, Wasm cannot emulate real network stacks, making it unsuitable for labs that require multiple communicating services (e.g., a vulnerable API backed by a database).
- **Docker containers**: sub-second startup for pre-pulled images, realistic network isolation via bridge networks, and direct support for existing vulnerable application images such as VAmPI and crAPI. Requires Docker socket access on the host.

No single technology covers the full range of lab types needed — from quick theory exercises to full-stack API security labs.

## Decision
Docker is the primary lab runtime for all full-stack, network, and application security labs. Wasm (via PyramidOS) is used for lightweight theory exercises and sandboxed scripting tasks where network emulation is not required. Each lab declares its runtime in `lab.yaml` using `type: docker` or `type: wasm`. `internal/labs/orchestrator.go` reads this field and dispatches to the appropriate runtime backend. Docker labs reference standard image names; Wasm labs reference a PyramidOS module path.

## Consequences
- Docker socket access is required on the host, which carries a privilege escalation risk if not properly scoped. This is documented in the operator deployment guide; rootless Docker is the recommended configuration.
- Wasm lab availability depends on the PyramidOS runtime being present. Operators can deploy a Docker-only configuration if PyramidOS is not available; the orchestrator degrades gracefully by rejecting `type: wasm` labs with a clear error rather than crashing.
- Maintaining two runtime backends increases orchestrator complexity but keeps the lab authoring interface uniform — authors declare a type and the platform handles dispatch.
- Docker image pull times affect first-run latency; operators are expected to pre-pull images at deployment time.
