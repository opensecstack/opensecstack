## ADR-012 — ML Inference Architecture: separate Python gRPC service

- Status: Accepted
- Date: 2026-04-25
- Phase: 4.2
- Owners: VertGuard core, Security ML
- Related: [`docs/ml-architecture.md`](../docs/ml-architecture.md),
  [`docs/ml-training-guide.md`](../docs/ml-training-guide.md),
  [`docs/ml-model-registry.md`](../docs/ml-model-registry.md),
  [`internal/prompt/corpus/TUNING.md`](../internal/prompt/corpus/TUNING.md),
  `proto/ml/v1/inference.proto`

## Context

The Phase 4.1 regex-only prompt scanner achieves macro-F1 ≈ 0.30 against
the labelled corpus, with BLOCKED recall at 0.17 and SUSPICIOUS F1 at 0.00
— see `internal/prompt/corpus/TUNING.md`. Threshold tuning cannot move
those numbers; ML is the only path forward for paraphrase / indirect /
encoded attacks.

We need to decide where the ML classifier lives and how the Go API talks
to it.

## Decision

VertGuard ships ML inference as a **separate Python service** that
exposes gRPC defined by `proto/ml/v1/inference.proto`. The Go scanner
keeps the regex prefilter and consumes the gRPC contract for the
borderline `SUSPICIOUS` band. The service is packaged as
`ghcr.io/opensecstack/vertguard-ml` and deployed via the
`deploy/helm/vertguard/charts/ml/` subchart, gated by `ml.enabled`.

## Reasons

- **Ecosystem reality.** The Python ML stack (transformers, torch,
  onnxruntime, peft, integrated-gradients) is several years ahead of
  any Go ML library. Trying to host inference in-process in Go would
  either pin us to a stale Go-native runtime or require CGO to a C++
  runtime — both worse than a clean network boundary.
- **Data residency.** SaaS APIs (OpenAI, Anthropic, Cohere) leak the
  raw user input to a third party. VertGuard's ASNI / NIS2 / AI Act
  posture is incompatible with that. The Python pod runs inside the
  customer's cluster.
- **Deploy + scale + GPU placement.** A separate pod can be sized,
  scheduled (GPU node pool), and scaled (HPA on p95 latency)
  independently of the Go API. In-process inference would couple
  CPU/RAM/GPU sizing to the API's HTTP load profile, which is the
  opposite shape.
- **Training pipeline lives in Python anyway.** The `python/training/`
  pipeline produces the artefact; serving it from a Python pod means
  zero conversion friction for the iteration loop. ONNX export is
  available but optional.

## Consequences

- **Extra hop.** ≤ 2 ms intra-cluster gRPC RTT. Acceptable inside the
  80 ms end-to-end p95 budget documented in `ml-architecture.md`. The
  hop only happens for borderline inputs (CLEAN / BLOCKED short-circuit
  in regex).
- **NetworkPolicy + soon-mTLS.** v1 is plaintext + NetworkPolicy.
  Phase 4.3.0 introduces SPIFFE-issued workload certs; Phase 4.3.1
  enforces mTLS-only ingress on the ML service. Documented in
  `ml-architecture.md` §Security boundary.
- **Two pods, two release channels.** Both images ride the same
  `vertguard/v*` tag (see `.github/workflows/release.yml`) so a tag
  push fans out to both registries. The Helm subchart's appVersion is
  pinned to the parent's, eliminating tag-skew.
- **Higher ops complexity.** Two Deployments, two HPAs, an extra
  Service and NetworkPolicy. Mitigated by playbook 3.10 in
  `operator-runbook.md` and by the `ml.enabled=false` default — operators
  who do not want ML do not pay the ops cost.

## Alternatives considered + rejected

- **ONNX-go (in-process Go inference).** Tooling and op-set support are
  not on parity with `onnxruntime`. Custom op kernels for transformer
  models (LayerNorm, GELU variants) lag, and there is no GPU story.
  **Rejected.**
- **HTTP REST instead of gRPC.** REST adds JSON parsing on the hot path
  and HTTP/1.1 head-of-line blocking. Empirical 2–4 ms vs gRPC's
  sub-ms. The latency budget cannot absorb it. gRPC also gives us
  streaming for `BatchScorePrompt` essentially free. **Rejected.**
- **Anthropic / OpenAI API as the classifier.** Data residency
  (cross-border PII), per-request cost (would dominate the unit
  economics), variable availability, and no fine-tuning path for
  ASNI's Albanian-language threats. **Rejected.**
- **Sidecar (same pod) Python container.** Couples the lifecycles —
  rolling the Go side cycles the ML model, which is exactly the
  property we wanted to avoid. **Rejected.**

## Validation

- `proto/ml/v1/inference.proto` is the contract; both sides build from
  the same file.
- `helm template deploy/helm/vertguard --set ml.enabled=true` must
  render both Deployments. `helm lint` should be clean.
- Smoke: regex-only and ML-enabled scan paths both pass `go test
  ./internal/prompt/...`. ML-on path additionally verified by an
  integration test against the stub backend.

## Follow-ups

- ADR-013 (when issued) — model registry approval and signing.
- ADR-014 (when issued) — mTLS enforcement on intra-cluster gRPC.
