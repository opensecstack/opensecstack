# Compatibility Matrix

Which platform versions work with which. This document is the
authoritative answer to "can IRFlow 1.1 talk to CITADEL 1.0?" — the
answer is in the table, not in a Slack thread.

For how versions are cut, see [release-process.md](./release-process.md).
For how features retire, see [deprecation-policy.md](./deprecation-policy.md).

## How to read this page

The matrix has three dimensions:

1. **Per-platform compatibility** — for each platform, which other
   platform versions it has been tested against.
2. **Ecosystem releases** — named bundles that pin a tested
   combination ("buy this if you want the blessed stack").
3. **Support windows** — how long each platform version continues to
   receive fixes.

## Current ecosystem release

### `ecosystem/v1.0.0-2026-Q2`

The first ecosystem release. Pins the v1.0.0 baseline.

| Platform | Version | Status | PQC status |
|---|---|---|---|
| APIGuard | `1.0.0` | Stable | Classical (no anchor signing) |
| NIS2 Compass | `1.0.0` | Stable | Classical (no anchor signing) |
| CITADEL | `1.0.0` | Stable | **Ed25519 anchors** — PQ migration scheduled v1.1/v2.0 |
| IRFlow | `1.0.0` | Stable | HMAC-SHA256 webhooks (PQ-safe); no signing |
| ThreatFlow | `1.0.0` | Stable | HMAC-SHA256 webhooks (PQ-safe); no signing |
| SDK (Go / Python / TS / Rust) | `1.0.0` | Stable (Rust currently Linux-only in CI) | HMAC verification only |

All platforms above are production-ready per the
[security maturity](./security-maturity.md) tier-1 profile.

### `ecosystem/v1.1.0-2026-Q2`

The 10-platform stack. All core platforms at v1.0.0. VertGuard AI-attack defence complete.

| Platform | Version | Status | PQC status |
|---|---|---|---|
| APIGuard | `1.0.0` | Stable | Classical (no anchor signing) |
| NIS2 Compass | `1.0.0` | Stable | Classical (no anchor signing) |
| CITADEL | `1.0.0` | Stable | **Ed25519 anchors** — PQ migration scheduled v1.1/v2.0 |
| IRFlow | `1.0.0` | Stable | HMAC-SHA256 webhooks (PQ-safe); no signing |
| ThreatFlow | `1.0.0` | Stable | HMAC-SHA256 webhooks (PQ-safe); no signing |
| OpenScrub | `1.0.0` | Stable | Classical (no signing) |
| CyberPath | `1.0.0` | Stable | Classical (no signing) |
| OpenCSIRT | `1.0.0` | Stable | Ed25519 peer identity; HMAC-SHA256 per-message |
| VertGuard | `1.0.0` | Stable | Classical (no signing); HMAC-SHA256 webhooks; gRPC mTLS via Istio/Linkerd |
| SDK (Go / Python / TS / Rust) | `1.0.0` | Stable (Rust currently Linux-only in CI) | HMAC verification only |

All platforms above are production-ready per the [security maturity](./security-maturity.md) tier-1 profile.

**New in v1.1.0 vs v1.0.0:**
- VertGuard v1.0.0 added (AI-attack defence, 28 endpoints, Python ML gRPC service)
- APIGuard: JWT multi-secret rotation, Redis sliding-window rate limiting, access token denylist, trusted-proxy depth stripping
- OpenCSIRT v1.0.0 added (CSIRT operations, CSAF 2.0, CITADEL WORM emission)
- OpenScrub v1.0.0 added (XDP/eBPF DDoS mitigation)
- CyberPath v1.0.0 added (security training)

### Post-quantum migration status

For the full roadmap see [post-quantum-roadmap.md](./post-quantum-roadmap.md)
and [ADR-011](../adrs/ADR-011-post-quantum-agility.md).

| PQC status | Meaning |
|---|---|
| **Classical** | Component does not perform public-key signing; no migration needed |
| **Ed25519 (v1.0)** | Uses Ed25519 for signatures today; migration to ML-DSA via hybrid mode in v2.0 |
| **Hybrid (v2.0+)** | Dual Ed25519 + ML-DSA signatures; either can verify |
| **PQ-default (v3.0+)** | ML-DSA is the default; Ed25519 retained only for historical verification |
| **PQ-only (v4.0+)** | Ed25519 signing removed; ML-DSA (or successor) exclusively |

Target: **PQ-default by v3.0 (2030)** — aligned with expected NIS3 transposition.

### Prior ecosystem releases

- `ecosystem/v1.0.0-2026-Q2` — initial 5-platform foundation (CITADEL, APIGuard, NIS2 Compass, IRFlow, ThreatFlow) + SDK


## Per-platform pair-wise matrix

For platform-to-platform compatibility. "Tested" means the combo is
exercised in CI; "Known-good" means reported-working by users but not
in CI; "Untested" means we have no data.

### IRFlow ↔ CITADEL

IRFlow calls CITADEL for MARSHAL evaluation and WORM emission.

|                | CITADEL 1.0.x | CITADEL 1.1.x (planned) | CITADEL 2.0.x (future) |
|----------------|:-:|:-:|:-:|
| **IRFlow 1.0.x** | Tested | Tested (upgrade path) | Migration required |
| **IRFlow 1.1.x** | Tested | Tested | Migration required |

**Compatibility rule:** IRFlow 1.x works with CITADEL 1.x regardless
of minor version. Both follow semver; minor bumps on either side are
non-breaking at the API level.

**Cross-major constraint:** when IRFlow 2.0 or CITADEL 2.0 lands,
the pairing becomes version-specific. A migration guide accompanies
each major bump.

### IRFlow ↔ ThreatFlow

ThreatFlow pushes IOC bundles to IRFlow webhook.

|                | ThreatFlow 1.0.x |
|----------------|:-:|
| **IRFlow 1.0.x** | Tested |

### IRFlow ↔ APIGuard

APIGuard pushes findings to IRFlow webhook.

|                | APIGuard 1.0.x |
|----------------|:-:|
| **IRFlow 1.0.x** | Tested |

### IRFlow ↔ NIS2 Compass

IRFlow submits Article 23 notifications to NIS2 Compass.

|                | NIS2 Compass 1.0.x |
|----------------|:-:|
| **IRFlow 1.0.x** | Tested |

### SDK ↔ Platforms

The SDK is shipped as a single version number across languages (Go,
Python, TypeScript, Rust). The SDK is tied to the HTTP contract of
the platforms.

|                       | Platforms 1.0.x | Platforms 1.1.x (planned) |
|-----------------------|:-:|:-:|
| **SDK 1.0.x**           | Tested | Tested (forward-compat) |
| **SDK 1.1.x (planned)** | Tested (backwards) | Tested |

**Compatibility rule:** SDK minor versions are forward and backward
compatible within the same major. SDK 2.0 accompanies platform 2.0;
cross-major combinations are supported only during their explicit
migration window.

### VertGuard ↔ CITADEL

VertGuard emits WORM evidence via CITADEL for all scan verdicts.

|                    | CITADEL 1.0.x |
|--------------------|:-:|
| **VertGuard 1.0.x** | Tested |

### VertGuard ↔ IRFlow

VertGuard emits incidents to IRFlow on HIGH-confidence detections.

|                    | IRFlow 1.0.x |
|--------------------|:-:|
| **VertGuard 1.0.x** | Tested |

### VertGuard ML gRPC service

The Python ML inference service (port 50051) is internal to VertGuard.
It is not part of the inter-platform compatibility surface — only VertGuard's Go server calls it.

| ML Backend | Min Go server | Notes |
|---|---|---|
| `stub` | any | No weights required; deterministic heuristics |
| `sklearn-cpu` | 1.0.0 | Requires model weights in `VERTGUARD_ML_*_MODEL_DIR` |
| `torch-cpu` | 1.0.0 | DistilBERT for prompt/phishing (requires `[ml]` extras) |

### Postgres

Every platform currently targets **PostgreSQL 16**. Earlier versions
(14, 15) are not in CI but are likely to work for read-heavy paths;
Gate 5 WORM append (CITADEL) has been baselined against 16
specifically.

- **Postgres 14-15:** best-effort. May work; not tested.
- **Postgres 16:** supported, tested.
- **Postgres 17:** untested. Expected to work; CI catches up when GA.

## Support windows

How long each version continues to receive fixes.

| Category | Example | Support ends |
|---|---|---|
| **Current stable** | v1.1.x (latest minor) | When v1.3 ships |
| **Previous stable** | v1.0.x | 12 months after v1.1 ships |
| **Older** | v0.9 and earlier | Unsupported immediately |
| **Ecosystem release** | `ecosystem/v1.0.0-2026-Q2` | 12 months from the release date |

**In practice:** two minor versions back are always supported for
security fixes. Everything older is archived.

For long-term deployments, the ecosystem release is your anchor —
deploying the pinned bundle gives you a guaranteed 12-month window
of support on that specific combination.

## Minimum versions by feature

Some cross-platform features require minimum versions on both sides.

| Feature | Requires |
|---|---|
| HMAC-signed webhooks with per-source secrets | IRFlow ≥ 1.0.0, upstream platforms ≥ 1.0.0 |
| CITADEL MARSHAL Gate 4 AUGUR rule_03 (DATA_EXPORT block) | CITADEL ≥ 1.0.0 (all rules ship in 1.0) |
| WORM chain anchor verification in `/worm/verify` | CITADEL ≥ 1.1.0 (planned) |
| Overlapping-secret rotation | IRFlow ≥ 1.1.0 and CITADEL ≥ 1.1.0 (both planned) |
| Playbook auto-triggering from webhooks | IRFlow ≥ 1.2.0 (planned) |
| Multi-writer WORM chain | CITADEL ≥ 2.0.0 (planned) |
| VIGIL health monitoring | CITADEL ≥ 1.2.0 + all platforms ≥ 1.1.0 (planned) |

## Protocol versions

HTTP APIs follow their own versioning at the URL path level:

- `/api/v1/...` — current
- `/api/v2/...` — introduced when breaking changes accumulate

A single platform server can expose multiple protocol versions during
a transition window. When `/api/v2/` lands, `/api/v1/` continues to
work for at least 12 months.

Schema / payload versioning within a protocol version follows the
deprecation policy ([deprecation-policy.md](./deprecation-policy.md)).

## Migration paths

When a major version ships, a migration guide is published at
`docs/migrations/vX-to-vY.md` (per platform or ecosystem-wide,
depending on scope).

Planned migration docs (not yet written):

- `docs/migrations/v1-to-v2-ecosystem.md` — ecosystem-wide v2.0 cut
- `citadel/docs/migrations/v1-to-v2.md` — CITADEL multi-writer chain
- `irflow/docs/migrations/v1-to-v2.md` — IRFlow 2.0 changes

These are written as part of the respective major release — never
before. Speculative migration docs drift from reality by the time
the migration actually happens.

## How to verify compatibility yourself

For any claimed combination:

```bash
# Deploy the specific versions
docker run ghcr.io/opensecstack/citadel:1.0.0
docker run ghcr.io/opensecstack/irflow:1.0.0

# Exercise the end-to-end path
curl -XPOST $IRFLOW/api/v1/incidents -d '{...}'
curl $CITADEL/api/v1/worm/verify
```

If the end-to-end path works, the combination is good for your
workload. File a GitHub issue with label `compatibility-report` if
you find a broken combo we claim works — we'll update the matrix.

## Updating this file

**When:** every release that changes cross-platform behaviour.

**Who:** the platform maintainer cutting the release, reviewed by
core maintainers per [CODEOWNERS](../.github/CODEOWNERS).

**How:**

1. Add a row / cell for the new version.
2. Mark cells with the most specific truth: `Tested`, `Known-good`,
   `Untested`, `Known-broken`.
3. Update the "Current ecosystem release" section if this is an
   ecosystem cut.
4. Update support windows — moving the previous-stable row forward
   when a new major / minor drops out.

Out-of-date entries are more dangerous than missing ones — a claim
of "Tested" for a combination that actually broke is how operators
lose trust. When in doubt, mark `Untested`.

## Related

- [Release process](./release-process.md)
- [Deprecation policy](./deprecation-policy.md)
- [Security maturity tiers](./security-maturity.md)
- [Deployment topology](./deployment-topology.md)
