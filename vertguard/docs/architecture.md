# VertGuard Architecture

VertGuard is the 10th opensecstack (SIN) platform — AI-attack defence.
This document describes the overall architecture spanning all 5
modules across 3 phases. For module-specific internals, see the
per-module docs (`module-1-media-authenticity.md`, etc.).

For the strategic rationale, see [ADR-010](../../adrs/ADR-010-vertguard-platform-strategy.md).
For the public comment period, see [RFC-0004](../../rfcs/RFC-0004-vertguard-platform.md).

## Guiding principles

1. **Two-layer ML separation.** Go orchestrates; Python infers. gRPC
   is the boundary. This isolates ML failures from the control plane.
2. **Model and dataset registries.** SHA-256-checksummed manifests;
   nothing committed to git.
3. **No outbound telemetry of inputs.** Privacy is a first-class
   requirement; content never leaves the deployment.
4. **Detections are WORM-logged.** Every positive classification
   produces a CITADEL WORM entry for audit and appeal.
5. **Fail-closed, not fail-open.** Misconfiguration (empty secrets,
   missing models) refuses to serve, not passes content through
   unchecked.

## Three-layer architecture

```
┌────────────────────────────────────────────────────────────┐
│ Transport + Orchestration (Go)                             │
│ chi router · middleware stack · DB access · client SDKs    │
│ Handles API, CITADEL integration, ThreatFlow integration,  │
│ audit chain, rate limiting, authentication                 │
└────────────┬───────────────────────────┬───────────────────┘
             │                           │
             ▼                           ▼
┌──────────────────────┐      ┌──────────────────────────────┐
│ Rust hot-path        │      │ Python ML service (Phase 4.2+)│
│ ─────────────────    │      │ ─────────────────────────────│
│ Pattern matching,    │      │ Model loading,                │
│ cryptographic        │◄────►│ inference, preprocessing,     │
│ verification,        │ gRPC │ scoring, postprocessing       │
│ stream processing    │      │                               │
└──────────────────────┘      └──────────────────────────────┘
```

Each layer has a distinct concern:

- **Go (transport + orchestration):** HTTP server, database access,
  outbound calls to CITADEL / ThreatFlow / NIS2 Compass, request-scoped
  logging, rate limiting, authorisation. Same pattern as the other 9
  platforms — familiarity matters.
- **Rust (hot paths):** C2PA verification via `c2pa-rs`, prompt
  injection pattern matching, audio fingerprinting, TripleHash
  computation. Memory-safe, performance-critical.
- **Python (ML inference, Phase 4.2+):** HuggingFace model zoo
  adapters, deep learning inference, preprocessing pipelines. Runs as
  a gRPC side-car; fault isolation from Go control plane.

## Module layout

VertGuard ships as one platform with five logical modules:

```
vertguard/
├── internal/
│   ├── api/              ← HTTP handlers, middleware, server
│   ├── media/            ← Module 1: media authenticity
│   ├── phishing/         ← Module 2: AI phishing (Phase 4.2)
│   ├── prompt/           ← Module 3: prompt injection defence
│   ├── identity/         ← Module 5: synthetic identity (Phase 4.3)
│   ├── threatfeed/       ← Module 4: AI threat intel
│   ├── db/               ← Postgres access layer
│   ├── citadel/          ← CITADEL MARSHAL + WORM client
│   ├── reporter/         ← Report generation dispatch
│   └── config/           ← Viper-backed configuration
├── rust/
│   ├── c2pa/             ← Module 1 (Phase 4.1)
│   ├── prompt-patterns/  ← Module 3 (Phase 4.1)
│   ├── audio-fingerprint/← Module 1/5 (Phase 4.2+)
│   └── triple-hash/      ← Evidence hashing (vantage-hash bridge)
├── python/
│   ├── ml_service/       ← Phase 4.2+ stub; gRPC server
│   └── reporter/         ← Jinja2 HTML report generator
├── web/                  ← React dashboard
├── tests/                ← Go + Python + fp regression suites
├── models/               ← Registry only; models downloaded
├── datasets/             ← Registry only; datasets downloaded
└── docs/                 ← All documentation
```

## Data flow — Module 3 (Prompt Injection, Phase 4.1)

Most representative example of the Phase 4.1 flow (no ML):

```
HTTP POST /api/v1/prompt/scan
  │
  ▼
chi middleware stack
  │ - auditLog (from before auth — attacker probes are logged)
  │ - metrics (Prometheus per-endpoint histograms)
  │ - JWT auth (HS256, reused pattern from IRFlow)
  │ - RBAC guard (requireWrite for scan, requireRead for results)
  │
  ▼
internal/api/handlers/prompt.go
  │
  ▼
internal/prompt/defender.go
  │
  ▼
rust/prompt-patterns (via FFI or subprocess)
  │ - OWASP LLM Top 10 pattern library
  │ - Indirect injection detection
  │ - Jailbreak pattern detection
  │ - Returns: matches[] with pattern ID + confidence + byte range
  │
  ▼
internal/prompt/scorer.go
  │ - Aggregates matches → scan result
  │ - Applies configured confidence thresholds
  │ - Classifies: CLEAN | SUSPICIOUS | BLOCKED
  │
  ▼
internal/citadel/connector.go
  │ - On BLOCKED: emit vertguard.detection.prompt_injection to WORM
  │ - WORM entry ID returned in response
  │
  ▼
internal/db/postgres.go
  │ - Persist scan metadata (not content — privacy)
  │
  ▼
HTTP response: { classification, confidence, matches[], worm_entry_id }
```

## Data flow — Module 1 (Media Authenticity, Phase 4.1 C2PA subset)

```
HTTP POST /api/v1/media/verify (multipart or URL)
  │
  ▼
internal/api/handlers/media.go
  │
  ▼
internal/media/authenticator.go
  │
  ▼
rust/c2pa (via FFI)
  │ - Parse C2PA manifest from media file
  │ - Validate signature chain against trusted certificate registry
  │ - Reconstruct provenance chain
  │ - Returns: ProvenanceResult
  │
  ▼
internal/media/evidence.go
  │ - Compute TripleHash of media content
  │ - Bundle provenance + hash + timestamp as evidence
  │
  ▼
internal/citadel/connector.go
  │ - Emit vertguard.detection.media_authenticity to WORM
  │ - Include manifest, signer, TripleHash
  │
  ▼
HTTP response: { authentic, provenance_chain, signer, worm_entry_id }
```

**Phase 4.1 note:** if the media has no C2PA manifest, result is
`{authentic: unknown, reason: "no manifest"}`. Deepfake detection
(ML) lands in Phase 4.2 for content without manifests.

## Data flow — Module 4 (AI Threat Intelligence Feed)

```
                              ┌──────────────┐
                              │ AI threat    │
                              │ sources:     │
                              │ - MITRE ATLAS│
                              │ - Public     │
                              │   advisories │
                              │ - Community  │
                              │   feeds      │
                              └──────┬───────┘
                                     │ scheduled poll
                                     ▼
                    ┌────────────────────────────────────┐
                    │ internal/threatfeed/collector.go   │
                    │ Normalise into ThreatFlow IOC      │
                    │ format with ai_attack_pattern type │
                    └────────────┬───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────────────────┐
                    │ internal/threatfeed/threatflow.go  │
                    │ Push via ThreatFlow SDK            │
                    └────────────┬───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────────────────┐
                    │ ThreatFlow IOC store               │
                    │ (with ai_attack_pattern tag)       │
                    └────────────────────────────────────┘
```

## gRPC boundary (Phase 4.2+)

The Go/Python boundary uses gRPC for type safety, streaming support,
and fault isolation. `python/ml_service/proto/vertguard.proto`
defines:

```protobuf
service MLInference {
  rpc ClassifyImage(ImageRequest) returns (ClassifyResponse);
  rpc ClassifyVideo(stream VideoFrameRequest) returns (stream ClassifyResponse);
  rpc ClassifyAudio(stream AudioChunkRequest) returns (ClassifyResponse);
  rpc ClassifyText(TextRequest) returns (ClassifyResponse);
  rpc HealthCheck(Empty) returns (HealthStatus);
}
```

Why gRPC (and not the alternatives):

| Alternative | Why rejected |
|---|---|
| CGO (embed Python in Go) | Fragile; Python GIL contention; one crash kills Go process |
| REST | Latency overhead; streaming support weaker |
| Shared memory | Complexity; cross-platform fragility |
| Unix domain sockets + MessagePack | Could work, but gRPC ecosystem is richer; we'd reinvent wheels |

The gRPC service runs as a **side-car** per VertGuard pod. One ML
service per Go server. Simpler ops than shared-cluster pattern; GPU
memory is duplicated but acceptable. Shared-cluster pattern deferred
to v1.x enterprise deployments.

## Model registry

`models/models.yaml`:

```yaml
- id: faceforensics-xceptionnet-v4
  module: 1
  task: deepfake-image
  source: https://github.com/ondyari/FaceForensics/releases/download/...
  sha256: 7a9f2c...
  size_mb: 425
  licence: open-research
  accuracy_benchmark: 0.87 # F1 on FaceForensics++ v2 test set

- id: sentence-transformers-allmini-v6
  module: 2
  task: email-classification
  source: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2
  sha256: 3e8d1f...
  size_mb: 90
  licence: apache-2.0
```

Models are downloaded at first startup via `models/download.sh`, which
verifies SHA-256 before writing. Missing or mismatched models = refuse
to start the Python ML service.

## Dataset registry

`datasets/datasets.yaml`:

```yaml
- id: faceforensics-test-v2
  source: https://github.com/ondyari/FaceForensics
  sha256_manifest: 2c8a9e...
  size_gb: 14.2
  licence: research-only
  usage: tests/ml/deepfake_accuracy_test.py

- id: ai-phishing-corpus-2026
  source: internal + public-research
  sha256_manifest: b1f3c2...
  size_mb: 180
  licence: cc-by-4.0
  usage: tests/ml/phishing_accuracy_test.py
```

Datasets are **not** downloaded by default — they're only needed for
accuracy benchmarking, not runtime. `tests/datasets/download.sh`
fetches them in CI or locally on demand.

## Integration with ecosystem

```
          ┌──────────┐
          │APIGuard  │
          │scan done │──────────┐
          └──────────┘          │ VertGuard
                                │ scans for
                                ▼ deepfake in
          ┌──────────┐    ┌──────────────┐
          │IRFlow    │◄───│  VertGuard   │
          │incident  │    │  detection   │
          │created   │    │  event       │
          └──────────┘    └──────┬───────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                    ▼            ▼            ▼
              ┌──────────┐  ┌─────────┐  ┌──────────┐
              │CITADEL   │  │Threat   │  │NIS2      │
              │WORM      │  │Flow IOC │  │Compass   │
              │evidence  │  │update   │  │Art.21    │
              └──────────┘  └─────────┘  └──────────┘
```

- **CITADEL:** every detection produces a WORM entry; MARSHAL gates
  any auto-response actions VertGuard proposes.
- **ThreatFlow:** AI-specific IOC feed (MITRE ATLAS-tagged indicators);
  enriches incidents with AI context.
- **IRFlow:** HARD_STOP-style detections (confirmed deepfake CEO voice,
  etc.) auto-create P1 incidents via webhook.
- **NIS2 Compass:** AI-attack-defence completion records feed
  Article 21(2) measures (e, h, j primarily).

## Persistence

PostgreSQL 16 schema (evolved per-migration):

- `scans` — scan metadata (not content); input hash, result, worm_entry_id
- `patterns` — active pattern-engine rules (can be updated without redeploy)
- `atlas_mappings` — MITRE ATLAS technique mappings
- `threat_iocs` — AI-specific IOCs collected and pushed to ThreatFlow
- `model_metadata` — loaded model versions + last-accuracy-check timestamps
- `detection_events` — summary of detections for dashboard queries
- `schema_migrations` — migration bookkeeping (append-only by convention)

**No raw content columns.** Privacy by schema design.

## Observability

- **`/health`** — liveness + DB ping; unauthenticated.
- **`/metrics`** — Prometheus scrape; unauthenticated (per ecosystem
  convention).
- **Structured JSON logging** via zerolog with `request_id`, `scan_id`,
  module tags.
- **CITADEL audit chain** — authoritative record of every positive
  detection.

Metric catalogue:

- `vertguard_scans_total{module, result}` — scan volume by module and
  classification
- `vertguard_pattern_matches_total{pattern_id}` — per-pattern match
  counter
- `vertguard_atlas_iocs_total{technique}` — per-ATLAS-technique IOC
  volume
- `vertguard_ml_inference_seconds{module}` — ML latency histograms
  (Phase 4.2+)
- `vertguard_model_accuracy{model_id}` — periodic accuracy check
  results (Phase 4.2+)

## Failure modes

| Failure | Impact | Mitigation |
|---|---|---|
| Python ML service down | Modules 1 (deepfake), 2, 5 return 503; Modules 3, 4 unaffected | Health check + auto-restart; Go service starts fine without ML |
| CITADEL unreachable | Detections not WORM-logged immediately | Local queue; retry on connectivity restore (v0.5+) |
| Model file corrupted | Python ML refuses to load; clear error | SHA-256 re-verify on startup; ops alert |
| ThreatFlow unreachable | IOC feed updates queued locally | Local queue; retry on connectivity restore |
| Pattern DB drift | Patterns missing / stale | Scheduled pattern-registry sync; manual `vertguard patterns update` |

## Scaling characteristics

| Axis | Property |
|---|---|
| Stateless request handling (Go) | Yes — VertGuard can run behind a load balancer |
| Shared database | Yes — PostgreSQL is single source of truth |
| Python ML side-car | One per Go pod; GPU per pod (v1.x explores shared-cluster) |
| Pattern engine (Rust) | In-process; near-zero overhead |

## Related

- [quick-start.md](quick-start.md)
- [api.md](api.md)
- [module-3-prompt-injection.md](module-3-prompt-injection.md)
- [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md)
- [grpc-ml-service.md](grpc-ml-service.md) — Phase 4.2 gRPC contract
- [../../adrs/ADR-010-vertguard-platform-strategy.md](../../adrs/ADR-010-vertguard-platform-strategy.md)
