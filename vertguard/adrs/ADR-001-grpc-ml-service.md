## ADR-001 — gRPC for Go↔Python ML service communication

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.2
- Owners: VertGuard core, Security ML
- Related: [`docs/architecture.md`](../docs/architecture.md),
  [`docs/grpc-ml-service.md`](../docs/grpc-ml-service.md),
  `proto/ml/v1/inference.proto`,
  [`internal/ml/`](../internal/ml/)

## Context

VertGuard's Go handlers need to call Python ML models for prompt
injection classification, phishing detection, and deepfake scoring.
The two runtimes cannot share memory safely. An IPC mechanism must be
chosen that keeps latency inside the 80 ms end-to-end p95 budget
documented in `docs/ml-architecture.md`.

Options evaluated: REST/HTTP+JSON, gRPC+protobuf, a message queue
(RabbitMQ / Redis Streams), and shared-memory via mmap.

## Decision

VertGuard uses **gRPC** (defined in `proto/ml/v1/inference.proto`) as
the transport between the Go API layer and the Python ML service. The
contract is shared — both sides build from the same `.proto` file. The
Python service is addressed via `MLConfig.GRPCURL` (env
`VERTGUARD_ML_GRPC_URL`).

## Reasons

- **Typed contract.** Protobuf schemas catch field-type mismatches at
  compile time rather than at runtime. REST/JSON silently coerces or
  drops unknown fields.
- **Latency.** Intra-cluster gRPC RTT ≤ 2 ms. Empirical comparison
  showed REST adding 2–4 ms of JSON serialisation overhead on the
  hot path — unacceptable inside an 80 ms budget.
- **Streaming.** `ClassifyVideo` requires server-streaming frames;
  gRPC bidirectional streaming covers this with no additional
  protocol work. REST would require SSE or WebSocket bolted on.
- **Message queues rejected.** Async queues decouple producers from
  consumers but add broker dependency, at-least-once delivery
  complexity, and meaningful median latency (5–50 ms queue depth)
  that breaks the synchronous scan API contract.
- **Shared memory rejected.** Cross-platform fragility; requires the
  Python and Go processes to be co-located on the same node with
  shared tmpfs — conflicts with independent pod scaling.

## Consequences

- **Protobuf compilation step.** `make proto` must run before `go
  build` when `.proto` files change. CI enforces this via `buf lint`
  + `buf generate`.
- **Extra operational surface.** gRPC health checks (`HealthCheck`
  RPC) must be wired into liveness probes. `ml.enabled=false` (the
  default) skips the gRPC dial entirely — operators who do not need
  ML do not pay the complexity cost.
- **Future streaming.** `BatchScorePrompt` streaming RPC is available
  essentially free once the transport is gRPC.

## Alternatives considered + rejected

- **REST/HTTP+JSON.** 2–4 ms JSON overhead on hot path; no native
  streaming. **Rejected.**
- **Message queue (Redis Streams).** Async-only; adds broker
  dependency; median latency incompatible with synchronous scan
  response. **Rejected.**
- **Shared memory (mmap).** Requires same-node co-location; complex
  framing protocol; no cross-platform story. **Rejected.**

## Validation

- `buf lint proto/` must pass clean.
- `go test ./internal/ml/...` covers dial, timeout, and circuit-open
  paths against the gRPC stub backend.
- `helm template deploy/helm/vertguard --set ml.enabled=true` must
  render a `Service` targeting the ML pod on the gRPC port.

## Follow-ups

- ADR-014 (when issued) — mTLS enforcement on intra-cluster gRPC.
- Phase 4.3 — SPIFFE-issued workload certs replacing NetworkPolicy
  as the primary isolation boundary.
