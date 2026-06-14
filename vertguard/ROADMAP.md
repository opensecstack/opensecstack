# VertGuard Roadmap

> Public roadmap for VertGuard — the 10th platform in the opensecstack
> (SIN) ecosystem. AI-attack defence delivered in three phases across
> 2026-2028.
>
> This roadmap complements the ecosystem-wide
> [ROADMAP.md § Phase 4](../ROADMAP.md#phase-4--ai-attack-defence-2026-q3--2028-q4)
> and the strategic decision recorded in
> [ADR-010](../adrs/ADR-010-vertguard-platform-strategy.md).

## Guiding principles

1. **No-ML first.** Modules that don't need ML ship first. ML modules
   depend on Phase 4.1 revenue + EU funding to staff.
2. **Detections are evidence.** Every positive classification produces
   a CITADEL WORM entry. False positives are bugs, not trade-offs.
3. **Supply-chain first.** Models and datasets are checksummed,
   registry-managed, never committed.
4. **NIS3-ready by 2028 Q3.** v1.0.0 lands aligned with the expected
   NIS3 consultation window.

## Phase 4.1 — Prompt Injection + AI Threat Intel (2026 Q3 – 2027 Q2)

Go + Rust only. No ML dependencies. Ships v0.1.0 by 2026 Q4.

### v0.1.0 (2026 Q4 target)

| Deliverable | Module | Status |
|---|:-:|:-:|
| Scaffold + docs + LICENSE + paperwork | — | ✅ In progress |
| Rust `prompt-patterns` crate with OWASP LLM Top 10 initial coverage | 3 | 🔄 Planned |
| Go orchestrator for prompt scanning | 3 | 🔄 Planned |
| API endpoint: `POST /api/v1/prompt/scan` | 3 | 🔄 Planned |
| Rust `c2pa` crate integration via `c2pa-rs` | 1 | 🔄 Planned |
| API endpoint: `POST /api/v1/media/verify` (C2PA-only) | 1 | 🔄 Planned |
| Go feed collector + MITRE ATLAS mapping | 4 | 🔄 Planned |
| API endpoints: `GET /api/v1/threatfeed/iocs`, `POST /api/v1/threatfeed/atlas` | 4 | 🔄 Planned |
| CITADEL integration: `vertguard.detection` event type | — | 🔄 Planned |
| ThreatFlow integration: AI-specific IOC push/pull | — | 🔄 Planned |
| React dashboard (Modules 3 + 4) | — | 🔄 Planned |
| Integration tests against live Postgres | — | 🔄 Planned |

### v0.2.0 – v0.4.0 (2027 Q1 – Q2)

- Pattern-engine expansion (20 → 50+ injection patterns)
- MITRE ATLAS coverage maturation (initial set → comprehensive)
- NeMo Guardrails adapter for LLM firewall pattern
- Llama Guard adapter (optional)
- Operator handbook hardening based on alpha feedback
- False-positive regression corpus expansion
- Performance benchmarks published

### Success metrics for Phase 4.1

- **Time-to-v0.1.0:** ≤ 6 months from scaffold completion
- **OWASP LLM Top 10 coverage:** ≥ 80% of documented patterns
- **False-positive rate on benign-prompt corpus:** ≤ 2%
- **MITRE ATLAS coverage:** ≥ 60% of techniques with public signatures
- **First paying pilot customer:** 2027 Q2 target

## Phase 4.2 — Python ML Layer (2027 Q1 – Q3)

Adds ML inference for Modules 1 (deepfake) and 2 (AI phishing).
Requires ML engineer hire(s) and EU funding (Horizon Europe +
Digital Europe Programme).

### v0.5.0 (2027 Q3 target)

| Deliverable | Module | Status |
|---|:-:|:-:|
| Python ML service scaffold (gRPC side-car) | — | 🔄 Planned |
| HuggingFace model zoo adapters | — | 🔄 Planned |
| Model registry (`models.yaml`) with SHA-256 checksums | — | 🔄 Planned |
| FaceForensics++ integration | 1 | 🔄 Planned |
| CLIP + ViT image deepfake detection | 1 | 🔄 Planned |
| Audio deepfake detection (Resemblyzer + SpeechBrain) | 1 | 🔄 Planned |
| LLM-email classification (sentence-transformers) | 2 | 🔄 Planned |
| AI chat message classification | 2 | 🔄 Planned |
| ML accuracy benchmark suite | — | 🔄 Planned |
| Adversarial robustness test harness | — | 🔄 Planned |
| Privacy-preserving inference (on-device option) | — | 🔄 Planned |

### v0.6.0 – v0.9.0 (2027 Q4 – 2028 Q2)

- Model zoo expansion (additional deepfake detection backbones)
- Accuracy benchmarking against new generation models
  (StyleGAN3, Midjourney v6+, DALL-E 4, Stable Diffusion XL+)
- GPU inference optimisation (batching, caching)
- Multi-tenant ML inference with per-tenant isolation
- A/B testing infrastructure for model variants

### Success metrics for Phase 4.2

- **v0.5 ship:** within 3 months of Phase 4.1 funding closing
- **Deepfake image accuracy:** ≥ 85% F1 on FaceForensics++ v2 benchmark
- **Audio deepfake accuracy:** ≥ 80% F1 on ASVspoof 2024 benchmark
- **AI phishing detection:** ≥ 90% F1 on public benchmark
- **Inference latency p95:** ≤ 500ms per image on mid-range GPU
- **Adversarial robustness gap:** ≤ 10% accuracy drop on adversarial
  inputs vs clean inputs

## Phase 4.3 — Synthetic Identity + v1.0 (2028 Q1 – Q3)

Closes the module set. Completes v1.0.0 with real-time video call
analysis. Aligned with NIS3 consultation period.

### v1.0.0 (2028 Q3 target)

| Deliverable | Module | Status |
|---|:-:|:-:|
| Python ML layer for GAN profile detection | 5 | 🔄 Planned |
| Real-time video call analysis (WebRTC plugin) | 5 | 🔄 Planned |
| Zoom / Teams / WebEx integration | 5 | 🔄 Planned |
| Voice clone detection during live calls | 5 | 🔄 Planned |
| v1.0.0 security audit complete | — | 🔄 Planned |
| v1.0.0 third-party penetration test | — | 🔄 Planned |
| Full documentation at v1.0 standard (33 docs) | — | 🔄 Planned |
| NIS3 readiness statement | — | 🔄 Planned |

### Success metrics for Phase 4.3

- **v1.0.0 ship:** 2028 Q3 or earlier
- **Real-time deepfake detection latency:** ≤ 200ms per video frame
- **False-positive rate on legitimate profiles:** ≤ 1%
- **NIS3-ready:** positioned as reference implementation in NIS3 consultation

## Post-v1.0 direction (2028 Q4+)

### v1.x (2028 Q4 – 2030)

- NIS3 consultation feedback integration
- EU Digital Services Act alignment
- Expanded language coverage for AI phishing (EU languages beyond English)
- Post-quantum C2PA migration path (aligned with upstream C2PA
  specification's PQ work)
- Hardware-accelerated inference (Intel OpenVINO, NVIDIA TensorRT)

### v2.0 (2030-2031)

- Federated detection (cross-CSIRT signature sharing via OpenCSIRT)
- AI-agent governance (DID-verified AI-agents under MARSHAL via
  pyramid-registry integration)
- VIGIL integration (CITADEL health-signal consumption)

### v3.0 (post-NIS3 mandate)

- Certified reference implementation status
- SOC 2 Type II certification
- NIS3 compliance attestation framework
- Multi-region deployment patterns documented

## Non-goals

- **Not a general-purpose ML platform.** VertGuard uses ML for
  AI-attack defence specifically; we don't expose generic ML APIs.
- **Not a content moderation service.** We detect AI-generated content
  and prompt attacks; moderation policy is the deployer's decision.
- **Not a cloud ML gateway.** VertGuard runs inference locally by
  default. Cloud-routed inference is an optional deployment mode, not
  the default.
- **Not a deepfake generator detector with 100% accuracy.** No such
  thing exists. We report confidence, not truth.

## Call for contributions

VertGuard is a Phase-4 platform — the last to start in the 10-platform
ecosystem. Early contributors have outsized influence on the
architecture. Specifically open for claim:

- **Rust prompt-patterns crate** (Module 3)
- **MITRE ATLAS mapping** (Module 4)
- **C2PA integration** (Module 1, Phase 4.1)
- **gRPC ML service scaffold** (Phase 4.2 preparation)
- **React dashboard** for Modules 3 + 4

Open an issue with label `claim-module` or `good-first-issue`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Related

- [../ROADMAP.md § Phase 4](../ROADMAP.md#phase-4--ai-attack-defence-2026-q3--2028-q4) — ecosystem-wide roadmap
- [RFC-0004](../rfcs/RFC-0004-vertguard-platform.md) — open community comment
- [ADR-010](../adrs/ADR-010-vertguard-platform-strategy.md) — strategic decision
- [docs/architecture.md](docs/architecture.md) — detailed architecture
