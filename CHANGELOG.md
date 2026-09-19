# opensecstack Ecosystem Changelog

All notable ecosystem-level changes are documented here.

Per-platform changelogs:
[APIGuard](apiguard/CHANGELOG.md) ·
[NIS2 Compass](nis2compass/CHANGELOG.md) ·
[CITADEL](citadel/CHANGELOG.md) ·
[IRFlow](irflow/CHANGELOG.md) ·
[ThreatFlow](threatflow/CHANGELOG.md) ·
[SDK](sdk/CHANGELOG.md)

For how releases are cut and ecosystem-release tags are produced, see
[docs/release-process.md](docs/release-process.md).

---

## [ecosystem/v1.3.0] - 2026-09-19

**Governance goes from audit-only to enforced, end to end.** Every platform now
calls CITADEL MARSHAL synchronously and fails closed on a refused or
unreachable governance check, instead of only forwarding events for the audit
trail. IRFlow and NIS2 Compass gain real two-person Separation-of-Duties
flows, and the SDK grows two more typed clients plus a shared password-hashing
module.

### CITADEL v1.1.0 — optional Permify-backed Gate 2 check

- Gate 2 (AuthZ) can now cross-check a periodically-synced Permify policy
  snapshot alongside the existing, unconditionally-enforced RBAC map. Disabled
  by default (`EnforcePermifyAuthz=false`); an unsynced role/action pair is
  always treated as PASS, and a known deny only warns until explicitly
  enabled. See [ADR-007](citadel/adrs/007-permify-gate2-snapshot.md).

### NIS2 Compass v1.1.0, IRFlow v1.1.0, APIGuard v1.1.0 — real governance enforcement

- **NIS2 Compass**: four privileged actions (control status update, artifact
  signing, assessment lock/unlock) now call CITADEL MARSHAL synchronously and
  fail closed (`403`/`503`) on a `REFUSE`/`HARD_STOP` verdict or an
  unreachable CITADEL. This replaces audit forwarding that was, in fact,
  completely broken — it posted to a route CITADEL never exposed, so every
  event silently failed regardless of configuration. Artifact signing now
  sends a genuine second identity (the preparer) as Verifier, rather than a
  placeholder.
- **IRFlow**: new propose → approve/reject incident-action flow. A second,
  distinct authenticated user must approve an action before CITADEL MARSHAL is
  ever evaluated — enforced both in the application layer and with a database
  constraint (`verifier_user_id <> operator_user_id`).
- **APIGuard**: scan initiation gains an optional two-person approval flow
  (`citadel.require_approval`), and scan creation now forwards the real
  authenticated caller's identity to CITADEL instead of a hardcoded
  placeholder user.

### sinauth SSO reaches APIGuard, IRFlow, and NIS2 Compass

- Each platform's own dashboard/API now authenticates via sinauth (OAuth 2.0 /
  OIDC, authorization_code + PKCE), matching the sinauth identity layer
  introduced in `ecosystem/v1.2.0`.
- **Note:** `ecosystem/v1.2.0` (below) described this SSO rollout as already
  ecosystem-wide; these platforms' own `[Unreleased]` sections had it listed
  as still-pending until this release. Flagging the discrepancy rather than
  silently resolving it — the per-platform changelogs are the more granular,
  code-level record and are what this entry is built from.
- ThreatFlow's own `[Unreleased]` section also lists sinauth SSO integration,
  CSAF advisory ingestion, and a governance-identity fix, but ThreatFlow is
  not built or published by this release's CI pipeline (`release.yml` covers
  APIGuard, NIS2 Compass, CITADEL, and IRFlow only), so those changes are not
  part of this ecosystem cut and stay under `[Unreleased]` until a release
  actually exercises them.

### SDK v1.1.0 — two more typed clients, shared password hashing

- New IRFlow and ThreatFlow typed clients (Go and Python), and a webhook
  retry helper with exponential backoff.
- New Argon2id (RFC 9106) password/API-key hashing module, shared between Go
  (`github.com/opensecstack/sdk/password`) and Python
  (`opensecstack-password`) with an identical PHC wire format so hashes
  verify cleanly across both languages. IRFlow is the first adopter.

---

## [ecosystem/v1.2.0] - 2026-05-23

**Single sign-on across the stack.** Introduces **sinauth**, a dedicated identity layer, and wires every platform to it over OpenID Connect.

### sinauth v1.0.0 shipped — identity layer

- **[sinauth/](sinauth/)** — OAuth 2.0 / OpenID Connect authorization server. One account grants access to all SIN platforms via single sign-on. What Auth0 is globally, sinauth is for SIN.
- Stack: Go API on `:8100`, PostgreSQL token store. Issuer `https://auth.sin.to`.
- OIDC Authorization Server core: authorization_code + PKCE (S256), RS256 token signing, JWKS endpoint, OpenID Connect discovery document, refresh tokens, SSO session management.
- Social login (Google, GitHub) and TOTP MFA (authenticator apps).
- OAuth2 client (platform) management with admin dashboard; bcrypt password hashing (cost 12); rate limiting on auth endpoints (5 req/min per IP); Docker + Helm deployment.
- Per-platform integration guides for all platforms in [sinauth/docs/integration/](sinauth/docs/integration/).
- Per-platform changelog: [sinauth/CHANGELOG.md](sinauth/CHANGELOG.md).

### Ecosystem-wide SSO integration

- **SDK:** new `sinauth` clients added — Go (`sdk/go/sinauth/`) and TypeScript (`sdk/typescript/sinauth/`).
- **Web clients:** OIDC popup login (`sinauth.ts`, authorization_code + PKCE, `/auth/callback`) wired into APIGuard, NIS2 Compass, OpenScrub, CyberPath, OpenCSIRT, SecureLab, and VertGuard dashboards.
- **Backends:** NIS2 Compass adds `app/sinauth.py` for OIDC token validation. APIGuard auth handler now forwards auth events to the CITADEL WORM chain and adds an access-token denylist with `POST /api/v1/auth/logout`.
- **Website:** new sinauth section on opensecstack.org.
- **Docs:** README, ECOSYSTEM, ARCHITECTURE, and `docs/security-architecture.md` (Layer 1 — Identity Fence) updated to describe sinauth as the identity layer.

---

## [ecosystem/v1.1.0] - 2026-05-10

**10-platform stack.** All core platforms at v1.0.0. VertGuard AI-attack defence complete.

### VertGuard v1.0.0 shipped (Phase 4 — complete)

- **[vertguard/](vertguard/)** delivered as a feature-complete Phase 4 platform — AI-attack defence. Date: 2026-05-10.
- Stack: Go API on `:8091`, Python ML gRPC service on `:50051`, React + Vite + TS dashboard on `:3009`, PostgreSQL 16, Rust crates (`c2pa-verify`, `audio-fingerprint`, `triple-hash`).
- **28 API endpoints** across 6 detection modules + admin + webhooks.
- **Phase 4.1 (v0.1.0):** Module 3 (Prompt Injection — OWASP LLM Top 10, MITRE ATLAS), Module 4 (AI Threat Feed — IOC store, ATLAS sync), Module 1 (Media/C2PA — Rust `c2pa-rs`, `--certs` PEM chain), Module 2 (AI Phishing), Module 6 (Identity Verification — replay window). All 28 routes registered. Integration tests: phishing, identity, media handlers.
- **Phase 4.2 (v0.5.0):** Python ML layer — `MediaModel` (GradientBoosting, C2PA metadata signals), `IdentityModel` (IsolationForest anomaly detector, 8-dim privacy-safe signal vector, FATF country risk scores). Both wired via gRPC `InferenceService` into Go handlers. Training configs included.
- **Phase 4.3 (v1.0.0):** Real-time video deepfake detection (WebSocket stream, CLIP 512-dim feature vector, temporal smoothing), voice clone detection (`AudioModel` on MFCC+spectral hash from Rust `audio-fingerprint`), Zoom/Teams/WebEx meeting plugin scaffolding (OAuth2 + HMAC webhook), `ScoreAudio` gRPC RPC added to proto.
- **Security audit checklist 100% complete:** mTLS (Istio + Linkerd policies), OPA Gatekeeper secret gate, `go mod tidy` CI gate, cstate status page, tabletop runbook (5 scenarios). Threat model updated with Phase 4.3 surface (TB-10/11/12, AT-4/AT-5).
- **54 docs** including `docs/INDEX.md`, NIS3 readiness statement, MITRE ATLAS mapping, operator runbook.
- **11 ADRs** (ADR-001 through ADR-011).
- Dashboard: Login, Dashboard, Scan, ThreatFeed (IOC table + ATLAS coverage tabs), VideoScan pages. Full i18n (English + Albanian).
- Per-platform changelog: [vertguard/CHANGELOG.md](vertguard/CHANGELOG.md).

### APIGuard — feature updates

- **JWT multi-secret rotation:** `SecretProvider` now holds up to 3 secrets (sliding list); `POST /api/v1/admin/auth/rotate` endpoint; `APIGUARD_AUTH_JWT_SECRETS` comma-separated env var with backward compat.
- **Redis sliding-window rate limiting:** Replaced fixed-window INCR+EXPIRE Lua script with sorted-set sliding window (`ZREMRANGEBYSCORE/ZCARD/ZADD/PEXPIRE`); accurate `Retry-After` header; fail-open on Redis error preserved.
- **Access token denylist:** New `POST /api/v1/auth/logout` endpoint; `TokenDenylist` TTL-bounded in-memory store; JWT validation middleware checks denylist on every request.
- **Trusted proxy depth stripping:** `APIGUARD_RATELIMIT_TRUSTED_PROXY_DEPTH` env var; `X-Real-IP` fallback when peer is trusted; `MustParseTrustedProxyCIDRs()` logs WARN on invalid CIDR entries.
- Per-platform changelog: [apiguard/CHANGELOG.md](apiguard/CHANGELOG.md).

### OpenCSIRT v1.0.0 shipped (Phase 3)

- **[opencsirt/](opencsirt/)** delivered as a feature-complete Phase 3 platform — national/sector CSIRT operations. Date: 2026-05-10.
- Stack: Go API on `:8088`, Python advisory subsystem on `:8089` (loopback-only, CSAF 2.0 schema validation + Jinja2 rendering), React + Vite + TS dashboard on `:3088`, PostgreSQL 16, optional Redis rendering cache.
- **Constituency directory** (`essential` / `important` / `sector`), **incident coordination** with IRFlow incident-import bridge, **CSAF 2.0 advisory authoring** (draft → review → approve → publish state machine, NDS Gate-3 enforced), **peer-CSIRT handshake** (Ed25519 long-term identity + HMAC per-message + ±5min replay).
- **CITADEL evidence emitter** posts exactly four event types: `opencsirt.incident_opened`, `opencsirt.incident_closed`, `opencsirt.advisory_published`, `opencsirt.escalation_sent` (HMAC-SHA256 signed, ±5-minute replay window).
- **Hardening:** silent error elimination (`_ = json.Unmarshal` → checked), outbox idempotency (`ON CONFLICT (event_id) DO NOTHING`), HMAC replay window drift fix (`drift < 0` bug), advisory Withdraw CITADEL event added, VertGuard subscriber deduplication.
- **ThreatFlow advisory→IOC pipeline**; **VertGuard integration** via `?from_vertguard_id=`.
- Per-platform changelog: [opencsirt/CHANGELOG.md](opencsirt/CHANGELOG.md).

### OpenScrub v1.0.0 shipped (Phase 2)

- **[openscrub/](openscrub/)** delivered as a feature-complete Phase 2 platform — XDP/eBPF DDoS mitigation. Date: 2026-05-09.
- Stack: Rust + Aya loader (privileged, CAP_BPF + CAP_NET_ADMIN), C eBPF data plane (LPM blocklist + per-CIDR rate-limit), Go API on port `:8087`, React + Vite + TS dashboard on `:3087`.
- ThreatFlow IOC puller (15-minute default cadence) reconciles the malicious-IP feed into the BPF blocklist map.
- CITADEL evidence emitter posts `openscrub.mitigation` and `openscrub.rule_change` events (HMAC-SHA256, ±5-minute replay window).
- Per-platform changelog: [openscrub/CHANGELOG.md](openscrub/CHANGELOG.md).

### CyberPath platform scaffolded (Phase 2 kickoff)

- Scaffolded CyberPath (Phase 2 kickoff). See [cyberpath/CHANGELOG.md](cyberpath/CHANGELOG.md).
- Strategic decision recorded in [ADR-012: CyberPath Platform Strategy](adrs/ADR-012-cyberpath-platform-strategy.md).

### Strategic decisions recorded

- **ADR-010: VertGuard Platform Strategy** — adds VertGuard as the 10th ecosystem platform (AI-attack defence), delivered in 3 phases.
- **ADR-011: Post-Quantum Cryptographic Agility** — commits the ecosystem to hash + signature agility with hybrid Ed25519/ML-DSA by v2.0, PQ-default by v3.0.

### Ecosystem documentation updated

- `.github/profile/README.md` — 10-platform count, VertGuard v1.0.0 production status, APIGuard new features.
- `ECOSYSTEM.md` — VertGuard row flipped to ✅ Production v1.0.0; platform count updated.
- `ROADMAP.md` — Version summary updated; all Phase 4 deliverables marked done; ecosystem release milestones updated.
- `docs/deployment-topology.md` — VertGuard row updated to v1.0.0; gRPC ML service marked active.
- `docs/compatibility-matrix.md` — New ecosystem release `ecosystem/v1.1.0` added.

## [Unreleased]

---

## [ecosystem/v1.0.0-2026-Q2]

**Milestone release.** Initial ecosystem v1.0.0 bundle. Pins the
5-platform foundation.

### Platforms at v1.0.0

- APIGuard v1.0.0
- NIS2 Compass v1.0.0
- CITADEL v1.0.0
- IRFlow v1.0.0
- ThreatFlow v1.0.0

### SDK at v1.0.0

- opensecstack/sdk v1.0.0 (Go + Python + TypeScript + Rust)

### Benchmarks (Intel Core i7-7600U, Go 1.24.4)

- TripleHash (100-byte payload): 1.52 µs
- WORM chain step (hash computation): 427 ns, 0 allocations
- WORM append (PostgreSQL 16, synchronous): 4.22 ms
- MARSHAL 5-gate evaluation (in-memory mock store): 7.55 µs mean
- Chain verification (1,000 entries): 10.19 ms

### Production-ready per security-maturity tier 1

NGOs, regional public administration, mid-sized enterprises, research
institutions. See
[docs/security-maturity.md](docs/security-maturity.md) for the full
matrix.

---

## [0.1.0] - 2025 Q1

### Platforms launched

- **APIGuard v0.1.0** — API security testing with OWASP API Top 10
  coverage (A1–A10), CVSS 3.1, SARIF output
- **NIS2 Compass MVP** — NIS2 Article 21(2) compliance assessment (all
  10 measures A–J), PDF reports, CITADEL webhook integration

### SDK

- opensecstack Go SDK v0.1.0 — typed clients for APIGuard and NIS2
  Compass, zero external HTTP dependencies
- opensecstack Python SDK v0.1.0 — typed clients with thread-safe
  token caching and proactive refresh

### Infrastructure

- Docker Compose for development, testing, and production stacks
- Kubernetes manifests (`deploy/k8s/`) for production deployment
- Multi-stage Docker builds (~50 MB APIGuard, minimal NIS2 Compass)
- GitHub Actions CI for APIGuard (Go + Rust + React) and NIS2 Compass
  (Python + React)

### Governance

- Architecture Decision Records: ADR-001 (Rust for parsing), ADR-002
  (Go for HTTP/orchestration)
- RFCs: template and submission process established
- SECURITY.md: responsible disclosure policy
- CONTRIBUTING.md: language-specific contribution standards
- CODE_OF_CONDUCT.md: community standards
- CLA.md: Contributor License Agreement
