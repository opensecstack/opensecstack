# opensecstack Development Standards

> Ecosystem-wide engineering guide for the opensecstack (SIN — Security
> Intelligence Network) monorepo. This file governs how work is done
> across **all 11 platforms + the CITADEL governance layer + the
> 4-language SDK**. Per-platform specifics live in each platform's own
> `README.md`, `CONTRIBUTING.md`, and `docs/`.

## Quality Philosophy

**opensecstack is production security infrastructure, not a demo.**

Every platform is at **v1.0.0 production**. Organisations deploy these
tools to meet real regulatory obligations (NIS2 Article 21/23, EU AI
Act) and to defend live infrastructure. A shortcut in a security tool
is not a missed deadline — it is a false sense of safety for the people
relying on it. "Good enough for now" is never acceptable. Every feature
must be production-ready, tested, and auditable when marked complete.

The defining property of this ecosystem is **auditability**: every
privileged action flows through CITADEL and is cryptographically
recorded. Code that weakens, bypasses, or silently fails the audit path
is a defect, regardless of whether tests pass.

## Non-Negotiable Standards

### Test Coverage

- Every Go service MUST pass `go test ./... -race` with **≥ 70 % total
  coverage** (CI enforces this; see [.github/workflows/ci.yml](.github/workflows/ci.yml)).
  **Temporary exception:** the Python and Rust SDKs
  ([sdk/python](sdk/python), [sdk/rust](sdk/rust)) gate CI at 55 % and
  50 % respectively (see [.github/workflows/sdk.yml](.github/workflows/sdk.yml)) —
  their test suites failed to even collect/build for the SDK's entire
  history until 2026-07-31, so 70 % was never actually reachable or
  measured. The floor is set just below current real coverage so it
  blocks regressions while tests are added back up to 70 %. Do not
  raise other platforms' floors down to match — this applies to the
  SDK only, and should be removed once SDK coverage reaches 70 %.
- Every Rust crate MUST pass `cargo test --workspace` and
  `cargo clippy --workspace -- -D warnings` (warnings are errors).
- Every Python service MUST pass its `pytest` suite (`pytest.ini` /
  `pyproject.toml` per platform) under Python 3.12.
- Parsers handling untrusted input (APIGuard Rust analyser, ThreatFlow,
  OpenScrub) MUST have fuzz/edge-case tests — malformed input is the
  threat model, not an edge case.
- APIGuard maintains explicit **false-positive tests** (`make test-fp`)
  against a known-clean target. Detection tools that cry wolf get
  ignored — protect signal quality.
- No feature is complete without passing tests in CI, not just locally.

### Code Quality

- All code must be type-safe and validated at the boundary: Go with
  explicit error handling (no swallowed errors), Rust with no
  `unwrap()` on untrusted paths, Python with type hints + Pydantic/
  dataclass validation, TypeScript in `strict` mode.
- No `TODO: fix later`, commented-out code, or `panic!`/`os.Exit` in
  library paths landing on `main`.
- Follow the **language-per-layer** strategy (see Architecture). Do not
  reach for Python where the layer calls for Go, or hand-roll crypto in
  Go where a Rust crate or the SDK already provides it.
- All inter-platform communication goes through the
  [opensecstack/sdk](sdk/) typed clients and event schemas — never
  hardcode another platform's wire format or invent an ad-hoc payload.
- Security defects are fixed immediately, not ticketed: this includes
  IDOR, missing authZ checks, replay windows wider than ±5 min on
  webhooks, secrets in code, and any path that skips CITADEL evaluation
  for a governed action.

### Governance & Audit (CITADEL)

CITADEL is the spine of the ecosystem. Treat it as non-optional:

- Every **privileged / governed action** must be submitted to CITADEL
  MARSHAL (the 5-gate engine: AuthN → AuthZ → NDS → AUGUR → WORM) and
  honour its verdict (`EXECUTE` / `REFUSE` / `HARD_STOP`).
- Audit-relevant events must be forwarded to the CITADEL WORM chain.
  Never write a parallel "shadow" log that bypasses TripleHash
  (SHA-256 + SHA-512 + BLAKE3) integrity.
- Separation of Duties (NDS, Gate 3) is enforced cryptographically:
  operator ≠ verifier. Do not add code paths that let one identity
  satisfy both roles.
- When adding a new governed capability, define its CITADEL Kerkese
  contract in the SDK first, then wire the platform to it.

### Production Readiness

- Every feature ships with: database migration (Alembic for Python,
  platform migration tooling for Go), API contract reflected in the
  SDK, frontend integration where a UI exists, and docs.
- Webhooks between platforms are **HMAC-SHA256 signed** with per-source
  secrets and a ±5-minute replay window. No exceptions.
- End-user and operator authentication is delegated to **sinauth** over
  OIDC (authorization_code + PKCE for browser apps). Validate sinauth
  RS256 tokens against the JWKS endpoint — do not mint your own user
  credentials or hand-roll an OAuth flow; reuse the SDK `sinauth`
  clients and the per-platform guides in
  [sinauth/docs/integration/](sinauth/docs/integration/).
- API/service clients are JWT-authenticated with RBAC (the 5 canonical
  roles: admin, operator, verifier, viewer, service).
- Passwords use the shared **Argon2id + server-side pepper** module
  ([sdk/go/password](sdk/go/password) / [sdk/python-password](sdk/python-password)) —
  byte-compatible PHC encoding across languages. Never roll your own.
- Build/CI failures are resolved, not documented or skipped.

### Documentation

- Every platform keeps its `README.md`, `CHANGELOG.md`, `docs/`, and
  ADRs current with what actually ships.
- Architectural decisions affecting more than one platform get an
  [ADR](adrs/); cross-cutting proposals get an [RFC](rfcs/).
- Regulatory logic (NIS2 measure mapping, Article 23 timers, CSAF/STIX
  conformance, fiscal/crypto signing) MUST carry explanatory comments —
  it encodes law and standards, not just behaviour.
- **All documentation, comments, and content are written in English.**

## Architecture Overview

**11 platforms + 1 governance layer + 1 SDK**, integrated through typed
SDK contracts and governed by CITADEL.

| Platform | Purpose | Stack | Licence | Status |
|----------|---------|-------|---------|--------|
| [**APIGuard**](apiguard/) | API security testing (OWASP API Top 10) | Go + Rust + Python + React | Apache 2.0 | ✅ v1.0.0 |
| [**NIS2 Compass**](nis2compass/) | NIS2 Art. 21/23 compliance | Python + Go + React | AGPL-3.0 | ✅ v1.0.0 |
| [**IRFlow**](irflow/) | Incident response orchestration | Go + Python | AGPL-3.0 | ✅ v1.0.0 |
| [**ThreatFlow**](threatflow/) | Threat intel (STIX 2.1, MITRE ATT&CK) | Rust + Go | Apache 2.0 | ✅ v1.0.0 |
| [**OpenScrub**](openscrub/) | DDoS mitigation (XDP/eBPF, GoBGP) | Rust + C + Go | Apache 2.0 | ✅ v1.0.0 |
| [**CyberPath**](cyberpath/) | Security training (Docker/Wasm labs) | Go + React + Rust + Python | Apache 2.0 | ✅ v1.0.0 |
| [**SecureLab**](securelab/) | Attack simulation & detection validation | Python + Rust + Go | Apache 2.0 | ✅ v1.0.0 |
| [**OpenCSIRT**](opencsirt/) | CSIRT ops (TAXII 2.1, CSAF 2.0) | Go + Python | AGPL-3.0 | ✅ v1.0.0 |
| [**VertGuard**](vertguard/) | AI-attack defence (prompt injection, C2PA, MITRE ATLAS) | Go + Rust + Python | AGPL-3.0 | ✅ v1.0.0 |
| [**SIN Community**](community/) | Developer knowledge hub | Go + React + TS + Meilisearch | Apache 2.0 | ✅ v1.0.0 |
| [**sinauth**](sinauth/) | Identity provider — OAuth 2.0 / OIDC single sign-on for all platforms | Go + PostgreSQL | Apache 2.0 | ✅ v1.0.0 |
| [**CITADEL**](citadel/) | Governance engine (MARSHAL, WORM, NDS, AUGUR) | Go | AGPL-3.0 | ✅ v1.0.0 |
| [**sdk**](sdk/) | Typed clients + event schemas + `sinauth` OIDC clients | Go · Python · TypeScript · Rust | Apache 2.0 | ✅ v1.0.0 |

> **Two cross-cutting layers** sit beneath the platforms: **sinauth**
> (identity — every platform delegates user/operator authentication to
> it over OIDC) and **CITADEL** (governance — every privileged action is
> evaluated and WORM-logged). SIN Community is the public knowledge hub
> (domain `sin.to`, Meilisearch-backed).

### Language-per-layer strategy

| Concern | Language | Why |
|---------|----------|-----|
| HTTP services, orchestration, CLI | **Go 1.24+** | Concurrency, single-binary deploy |
| Parsing untrusted input, crypto, regex-heavy analysis | **Rust 1.76+** | Memory safety on security-critical paths |
| ML inference, data science, report templates | **Python 3.12** | HuggingFace, pandas, Jinja2, ReportLab |
| Dashboards / UIs | **React + TypeScript (strict)** | Type-safe component ecosystem |
| Kernel-level packet processing | **C + Rust/Aya** | XDP/eBPF requires it |
| Persistence | **PostgreSQL 16+** | JSONB, RLS, WORM tables for CITADEL |

### SDK contracts (the only sanctioned integration path)

All cross-platform data flows through versioned schemas in the SDK:

| Contract | Format | Producers → Consumers |
|----------|--------|-----------------------|
| Scan Result | JSON v1 | APIGuard → IRFlow, ThreatFlow, NIS2 Compass |
| IOC Bundle | STIX 2.1 v1 | ThreatFlow → OpenScrub, IRFlow, OpenCSIRT |
| Incident Record | JSON v1 | IRFlow → NIS2 Compass, OpenCSIRT, CITADEL |
| Compliance Evidence | JSON v1 | NIS2 Compass → CITADEL |
| CITADEL Kerkese | JSON v2.0 | Any platform → CITADEL (MARSHAL input) |
| Advisory | CSAF 2.0 v1 | OpenCSIRT → ThreatFlow |
| Simulation Result | JSON v1 | SecureLab → IRFlow, OpenScrub, ThreatFlow, VertGuard |
| AI-Attack Detection | JSON v1 | VertGuard → CITADEL, IRFlow, ThreatFlow |
| Content Provenance | C2PA + JSON v1.3 | VertGuard → CITADEL (WORM evidence) |

CyberPath's WORM audit events to CITADEL (lesson/quiz completions,
certification issuance/revocation) already flow through the CITADEL
Kerkese contract above — there is no separate "Training Record" SDK
schema, and none should be added for it.

CyberPath ↔ NIS2 Compass is **not** SDK-mediated: per
[ADR-014](adrs/ADR-014-cyberpath-nis2compass-integration-direction.md),
NIS2 Compass pulls directly from CyberPath's own REST API
(`GET /api/v1/coverage/{user_id}`, `GET /api/v1/cyberpath/recommend`
— see [cyberpath/docs/api.md](cyberpath/docs/api.md)), not through a
versioned `sdk/` schema. A prior version of this table listed a
`Training Record | JSON v1 | CyberPath → NIS2 Compass, CITADEL` row
describing a push relationship and an SDK schema; neither ever
existed (no `TrainingRecord` type under `sdk/`, and the push target
endpoints were never implemented on the NIS2 Compass side). The row
was removed rather than "fixed" — this integration correctly sits
outside the SDK-contract table.

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full data-flow map and
[ARCHITECTURE.md](ARCHITECTURE.md) for the technical deep-dive.

## Repository Structure

```
opensecstack/                  ← monorepo
├── apiguard/      nis2compass/   irflow/      threatflow/
├── openscrub/     cyberpath/     securelab/   opencsirt/
├── vertguard/     community/     citadel/     sdk/
├── deploy/        ← Docker Compose + K8s/Helm for the full stack
├── docs/          ← ecosystem-level docs (security, topology, PQ roadmap)
├── adrs/  rfcs/   ← Architecture Decision Records / Request for Comments
└── website/       ← opensecstack.org (Vite + TS)
```

Each platform is self-contained: its own `go.mod` / `pyproject.toml` /
`Cargo.toml`, `Makefile`, `Dockerfile`, `docker-compose.yml`, `docs/`,
and `adrs/`. There is no shared `go.mod` — platforms integrate through
the SDK, not through shared source.

## Local Development

**Each platform has a `Makefile` — use it.** The targets are
consistent across platforms even though the underlying toolchains
differ.

```bash
# Common per-platform targets (from inside a platform dir)
make dev          # start local stack with hot reload (docker compose)
make test         # full test suite (Rust + Go + integration as applicable)
make lint         # golangci-lint / cargo clippy / eslint
make fmt          # gofmt / cargo fmt / prettier
make migrate      # apply pending DB migrations
make bench        # performance benchmarks
```

Example — APIGuard runs Rust + Go + a React web app together:

```bash
cd apiguard
make dev                       # full stack, hot reload
make test                      # cargo test + go test + integration + FP
make test-fp                   # false-positive suite only
```

### Full ecosystem (Docker Compose)

```bash
cp deploy/.env.example deploy/.env     # fill in REQUIRED secrets — compose
                                       # fails loudly if they are unset
docker compose -f deploy/docker-compose.yml up -d
```

CITADEL is wired separately and merged in for full integration — the
ecosystem compose points platforms at `http://citadel-api:8099`. See
[deploy/](deploy/) for the K8s/Helm manifests.

### Local ports

| Service | Port |
|---------|------|
| APIGuard API / Web | 8080 / 3000 |
| NIS2 Compass API / Web | 8090 / 3001 |
| ThreatFlow API | 8091 |
| IRFlow API | 8083 |
| SIN Community API | 8089 |
| CITADEL API | 8099 |
| sinauth (identity provider) | 8100 |
| VertGuard API / Dashboard | 8091 / 3009 |
| PostgreSQL | 5432 |
| Redis | 6379 |

> Ports overlap between the single-platform dev composes and the
> ecosystem compose; run one or the other, not both, or remap.

### Migrations

- **Python (NIS2 Compass, etc.):** Alembic — `alembic upgrade head`,
  config per platform (`alembic.ini`).
- **Go platforms:** SQL migrations under each platform's `migrations/`,
  applied via `make migrate`.
- Never edit an applied migration — add a new one.

## CI/CD Pipeline

**Workflow:** [.github/workflows/ci.yml](.github/workflows/ci.yml) —
"Ecosystem CI" on GitHub Actions.

- Runs on push to `main`/`develop` and PRs targeting `main`.
- **Path-filtered:** PRs only run jobs for changed components
  (`apiguard/**`, `nis2compass/**`, `citadel/**`, `sdk/**`, …); branch
  pushes exercise **everything**.
- Per-component jobs: `test-*` (Go with `-race` + Rust unit tests),
  `lint-*`. Go coverage gate is **70 %** and fails the build below it.
- SDK has its own publish workflows (`sdk-go-publish`,
  `sdk-python-publish`, `sdk-typescript-publish`); releases via
  `release.yml`; nightly via `nightly.yml`.

**Before pushing**, run the affected platform's gates locally:

```bash
cd <platform> && make lint && make test
```

Do not rely on CI to catch what `make lint && make test` would catch
locally.

## Security & Maturity

v1.0.0 maps to deployment tiers honestly — see
[docs/security-maturity.md](docs/security-maturity.md):

| Profile | Verdict |
|---------|---------|
| **Standard** (single region, trusted operator) | Production-ready |
| **Elevated** (multi-region, multi-tenant, zero-trust) | Production-ready with Vault + service mesh + OpenTelemetry |
| **High assurance** (banking Tier 1, national CSIRTs, NIS2 essential) | Not yet — wait for v1.1 (JWKS, mTLS, third-party audit) |

**Cross-platform guarantees** (do not regress these): every privileged
action MARSHAL-evaluated; every decision WORM-logged with TripleHash;
Ed25519 anchors every 100 entries; SoD at protocol level; HMAC-signed
replay-protected webhooks; JWT + RBAC; Argon2id + pepper hashing; NIS2
Art. 21(2)/23 by design.

**Post-quantum:** algorithm-agility is a v1.1+ concern (hybrid Ed25519
+ ML-DSA by v2.0). When adding signatures, include an algorithm
identifier field — never hardcode the primitive. See
[docs/post-quantum-roadmap.md](docs/post-quantum-roadmap.md) and
[ADR-011](adrs/ADR-011-post-quantum-agility.md).

**Reporting vulnerabilities:** [SECURITY.md](SECURITY.md), plus each
platform's own `SECURITY.md` with scope and SLA.

## Licensing (know which bucket you are touching)

| Category | Licence | Platforms |
|----------|---------|-----------|
| Security tools (CI/CD-embeddable) | Apache 2.0 | APIGuard, ThreatFlow, OpenScrub, CyberPath, SecureLab |
| Governance (copyleft) | AGPL-3.0 | CITADEL, IRFlow, NIS2 Compass, OpenCSIRT, VertGuard |
| Community | Apache 2.0 | SIN Community |
| SDK | Apache 2.0 | opensecstack/sdk |

Governance platforms are AGPL because modifications to the audit trail,
compliance reporting, or CSIRT operations must remain open. Do not copy
AGPL code into an Apache-licensed platform.

## Ownership

**You own every line of code in this monorepo.** Code written in a
previous session is still your code. Never dismiss a failure as
"pre-existing" or "not caused by my change." If something is broken,
debug it, fix it, and prove the fix. Check git history, ADRs, RFCs, and
the platform's `CHANGELOG.md` for context. There is no
"someone else's platform" — it is all yours.

## Agent Behaviour

### Plan before building

- Enter plan mode for any non-trivial task (3+ steps, or anything
  touching a contract, a migration, or the CITADEL audit path).
- If an approach goes sideways, STOP and re-plan — do not keep pushing a
  broken approach.

### Respect platform boundaries

- A change to one platform's behaviour that another platform consumes
  is an **SDK contract change** — update the schema and bump its version
  deliberately; do not break consumers silently.
- Keep work scoped to the relevant platform directory; cross-platform
  changes need an ADR/RFC.

### Subagent hygiene

- Use subagents liberally to keep the main context clean — one focused
  task per subagent.
- Offload research, exploration, and parallel analysis across platforms.

### Prove it works

- Never mark a task complete without proof: run the platform's
  `make test`, hit the API, load the UI, check the WORM chain verifies.
- For detection/parsing changes, run the false-positive suite — a fix
  that adds noise is not a fix.
- Ask: "Would a staff security engineer approve this?"

### Self-correction

- After any correction from the user, update memory with the pattern so
  the same mistake does not recur.
- If a fix feels hacky: "Knowing everything I know now, implement the
  elegant solution."

### Language

- All code, comments, docs, and content: **English**.
- In conversation, mirror the user's language (Albanian ↔ Albanian,
  English ↔ English).

## When Making Decisions

Ask: **"Is this auditable, memory-safe, and production-ready — or am I
cutting a corner in security infrastructure?"** People deploy
opensecstack to meet legal obligations and defend real systems. If the
answer is the latter, invest the time to do it right.

---

_Ecosystem standards. Per-platform detail lives in each platform's
`README.md` and `docs/`._
