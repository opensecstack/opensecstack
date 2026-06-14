# VertGuard — AI-Attack Defence Platform

> **Status:** scaffold / pre-v0.1.0. Phase 4.1 modules (Prompt Injection
> Defence + AI Threat Intelligence Feed + C2PA provenance) in active
> development. Phase 4.2 (deepfake, AI phishing) and Phase 4.3
> (synthetic identity) scheduled for 2027 and 2028 respectively.
>
> See [RFC-0004](../rfcs/RFC-0004-vertguard-platform.md) for the open
> community comment period (deadline 2026-05-20) and
> [ADR-010](../adrs/ADR-010-vertguard-platform-strategy.md) for the
> platform strategy rationale.

VertGuard is the 10th platform in the opensecstack (SIN) ecosystem —
and the first OSS AI-attack defence platform targeted at NIS-scope
European organisations. It covers threats that classical
cybersecurity tools do not address: deepfakes (image, video, audio),
AI-generated phishing, prompt injection against LLM applications, AI
threat intelligence, and synthetic identity fraud.

## Module overview

VertGuard ships as a single platform with 5 logical modules delivered
across 3 phases:

| # | Module | Purpose | Phase | Status |
|:-:|---|---|:-:|---|
| 1 | **Media Authenticity** | C2PA provenance + deepfake detection (image/video/audio) | 4.1 (C2PA) + 4.2 (ML) | 🔨 Scaffold |
| 2 | **AI Phishing Detection** | LLM-generated email/chat classification | 4.2 | 📋 Planned |
| 3 | **Prompt Injection Defence** | OWASP LLM Top 10 scanner + LLM firewall integration | **4.1** | 🔨 Active |
| 4 | **AI Threat Intelligence Feed** | AI-specific IOCs, MITRE ATLAS mapping, ThreatFlow integration | **4.1** | 🔨 Active |
| 5 | **Synthetic Identity Detection** | GAN-generated profiles + real-time video call analysis | 4.3 | 📋 Planned |

## Why VertGuard exists

By 2026 AI-generated threats are mainstream. AI-generated phishing
has grown 400% in 24 months. Voice-clone CEO fraud has caused €25M+
confirmed losses. Prompt injection is OWASP LLM Top 10 #1.

None of this is addressed by classical cybersecurity platforms.
Commercial alternatives (Reality Defender, Lakera, Protect AI) are
SaaS-only, non-EU-sovereign, and cost €30k-€300k/year — pricing out
the NIS-scope organisations most exposed to these threats.

NIS3 (expected 2030-2032) is projected to mandate AI-attack defence
for essential entities. VertGuard targets **v1.0.0 stable by the
NIS3 transposition window**.

## Quick start (Phase 4.1 preview)

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/vertguard

# Phase 4.1 scope — prompt injection + AI threat feed, no ML required
cp .env.example .env
docker compose up -d

# Scan a prompt
curl -X POST http://localhost:8091/api/v1/prompt/scan \
  -H "Content-Type: application/json" \
  -d '{"input": "Ignore previous instructions and..."}'

# Full quick-start: docs/quick-start.md
```

Full deployment guide: [docs/configuration.md](docs/configuration.md),
topology in [../docs/deployment-topology.md](../docs/deployment-topology.md).

## Architecture at a glance

```
                      ┌──────────────────────────┐
                      │    VertGuard API (Go)    │
                      │    :8091                 │
                      └──────────┬───────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        ▼                        ▼                        ▼
┌───────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  Rust layer   │      │  Python ML layer │      │  Integrations    │
│  (Phase 4.1)  │      │  (Phase 4.2+)    │      │                  │
│               │      │                  │      │  → ThreatFlow    │
│  • c2pa-rs    │      │  • gRPC :50051   │      │  → CITADEL WORM  │
│  • prompt     │      │  • HuggingFace   │      │  → IRFlow (webhook)
│    patterns   │      │  • FaceForensics │      │                  │
│  • audio-fp   │      │  • sentence-     │      └──────────────────┘
│               │      │    transformers  │
└───────────────┘      └──────────────────┘
```

- **Go**: orchestration, HTTP API, CITADEL + ThreatFlow integration,
  pattern engine coordination
- **Rust**: C2PA bindings (via `c2pa-rs`), prompt injection pattern
  matching, audio fingerprinting
- **Python ML** (Phase 4.2+): gRPC side-car for inference, HuggingFace
  model zoo adapters
- **Model registry** (`models.yaml`): SHA-256 checksums, no models in
  git
- **Dataset registry** (`datasets.yaml`): same pattern for test data

Full architecture: [docs/architecture.md](docs/architecture.md).

## Endpoints (Phase 4.1)

| Method | Path | Module | Notes |
|---|---|---|---|
| `GET` | `/api/v1/health` | core | Liveness + DB ping |
| `POST` | `/api/v1/media/verify` | 1 | C2PA provenance only in Phase 4.1 |
| `POST` | `/api/v1/prompt/scan` | 3 | OWASP LLM Top 10 scan |
| `GET` | `/api/v1/threatfeed/iocs` | 4 | AI-specific IOC feed |
| `POST` | `/api/v1/threatfeed/atlas` | 4 | MITRE ATLAS mapping |

Full API reference: [docs/api.md](docs/api.md).

## Authentication

VertGuard authenticates users via sinauth SSO — the SIN ecosystem's
OIDC identity provider. The web dashboard uses a `sinauth.ts` client
(popup login, `/auth/callback`) implementing the authorization_code +
PKCE (S256) flow. The API validates RS256-signed access tokens against
the sinauth JWKS endpoint (`https://auth.sin.to/.well-known/jwks.json`).
See the [sinauth integration guide](../sinauth/docs/integration/vertguard.md) for setup details.

## Configuration

Full reference: [docs/configuration.md](docs/configuration.md).

Minimum required env vars:

```bash
VERTGUARD_DB_URL=postgres://...
VERTGUARD_CITADEL_API_URL=https://citadel.internal
VERTGUARD_CITADEL_KEY_SECRET=<hmac secret>
VERTGUARD_THREATFLOW_API_URL=https://threatflow.internal
VERTGUARD_THREATFLOW_KEY_SECRET=<hmac secret>
```

## License

AGPL-3.0. VertGuard is a governance-adjacent platform; copyleft
prevents closed-source forks of AI-attack defence infrastructure.
Tool platforms (APIGuard, ThreatFlow, SDKs) remain Apache-2.0. See
[LICENSE](LICENSE) for the rationale.

## Development status

- **Phase 4.1 active** (2026 Q3–Q4): Modules 3, 4, and partial 1 (C2PA only)
- **Phase 4.2 planned** (2027 Q1–Q3): ML layer for Modules 1 + 2
- **Phase 4.3 planned** (2028 Q1–Q3): Module 5 + real-time video call

See [ROADMAP.md](ROADMAP.md) for the detailed timeline.

## Contributing

Phase 4.1 modules are open for contribution now. Good first issues
are labelled in GitHub. See [CONTRIBUTING.md](CONTRIBUTING.md).

Contributors with ML expertise who want to start Phase 4.2 modules
(deepfake detection, AI phishing) earlier than planned — please open
an issue with label `phase-4.2-claim`; we'll work with you on
sequencing.

## Related

- [RFC-0004: VertGuard — AI-Attack Defence Platform](../rfcs/RFC-0004-vertguard-platform.md)
- [ADR-010: VertGuard Platform Strategy](../adrs/ADR-010-vertguard-platform-strategy.md)
- [ECOSYSTEM.md](../ECOSYSTEM.md) — full 10-platform ecosystem overview
- [docs/deployment-topology.md](../docs/deployment-topology.md) — ports, network segments
- [SECURITY.md](SECURITY.md) — vulnerability reporting for VertGuard
- [docs/security/](docs/security/) — audit-readiness package (threat
  model, checklist, pentest scope, disclosure, compliance map,
  pre-audit plan)
- [CHANGELOG.md](CHANGELOG.md)

## Security

VertGuard maintains a public security policy ([SECURITY.md](SECURITY.md))
and an external-audit-readiness package under
[docs/security/](docs/security/). Vulnerability reports go through
the GitHub Security Advisory channel; see
[docs/security/disclosure.md](docs/security/disclosure.md) for SLA
and safe-harbour terms.
