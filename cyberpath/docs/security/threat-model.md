## CyberPath Threat Model

STRIDE-lite + attack-tree analysis for the CyberPath training and
certification platform (v1.0.0 target scope). Companion to
`SECURITY.md` (which sets the four-axis high-level model) and the
per-module implementation files cited inline.

Scope: Go API server, React frontend, Rust Wasm sandbox host
(v1.0.0+), Postgres, CITADEL emit client, NIS2 Compass coverage /
recommend endpoints, IRFlow webhook consumer, content registry,
certification signer. Docker-based lab runtime (v1.0.0) is modelled
but is the stop-gap; the threat surface is dominated by the
wasmtime-based runtime that lands in v1.0.0.

### 1. System overview

```
                                  Internet / Learner workstation
                                           │ (TLS-terminated upstream)
                                           ▼
                            ┌──────────────────────────────┐
                            │  Ingress / reverse proxy     │
                            │  (cert-manager + nginx /     │
                            │   ALB / Gateway API)         │
                            └──────────────┬───────────────┘
                                           │ HTTP :8086, WS upgrade
                                           ▼
        ┌────────────────────────────────────────────────────────────┐
        │  CyberPath API (Go, distroless nonroot)                    │
        │  ────────────────────────────────────────────────────────  │
        │  RequestID → Logger → Metrics → Recovery → Timeout(60s)    │
        │  /api/v1/* → Audit MW → Auth MW (opensecstack/sdk) → RL    │
        │  Modules: path, quiz, lab, cert, citadel, coverage, content│
        └─┬────────────┬───────────────┬──────────────┬──────────────┘
          │            │               │              │
          ▼            ▼               ▼              ▼
   ┌────────────┐ ┌─────────────┐ ┌────────────┐ ┌───────────────┐
   │ Sandbox    │ │ Postgres    │ │ CITADEL    │ │ NIS2 Compass  │
   │ host (Rust │ │ (users,     │ │ WORM emit  │ │ inbound       │
   │ + wasmtime)│ │  completions│ │ (HMAC-     │ │ (coverage /   │
   │ per-       │ │  content_   │ │  SHA256)   │ │  recommend)   │
   │ session    │ │  versions,  │ └────────────┘ └───────────────┘
   │ instance   │ │  lab_       │       │              ▲
   └─────┬──────┘ │  sessions)  │       ▼              │
         │        └─────────────┘  upstream WORM       │
         ▼                         (immutable)         │
   ┌────────────┐                                ┌────────────┐
   │ Lab images │                                │ IRFlow     │
   │ (signed,   │                                │ webhook    │
   │ sha256-    │                                │ inbound    │
   │ pinned)    │                                │ (HMAC)     │
   └────────────┘                                └────────────┘
```

### 2. Trust boundaries

| # | Boundary | Crossing | Auth/integrity control |
|---|---|---|---|
| TB-1 | Internet ↔ ingress | TLS terminates upstream; HTTP on 8086 inside cluster | TLS at ingress, NetworkPolicy gates pod ingress |
| TB-2 | Ingress ↔ API | HTTP/JWT (opensecstack/sdk) | sdk auth middleware (JWT verify + role check) |
| TB-3 | Operator ↔ admin endpoints | JWT role=operator/admin | sdk `RequireAdmin`-style wrapper |
| TB-4 | Instructor ↔ content endpoints | JWT role∈{instructor,admin} | content-author trust hierarchy (see §4.7) |
| TB-5 | Learner ↔ lab WS | WS upgrade carries JWT | per-session token; rejected on mismatch with `lab_sessions.user_id` |
| TB-6 | API ↔ Postgres | TCP + password (`ssl_mode=require` in prod) | DB credentials from K8s Secret, rotated 180d |
| TB-7 | API ↔ Sandbox host | Loopback gRPC/HTTP, cluster-local | mTLS within cluster; sandbox host runs in same pod or sidecar |
| TB-8 | Sandbox host ↔ Wasm guest | wasmtime ABI | **Most sensitive boundary.** Enumerated host functions only; no host FS; fuel + memory caps |
| TB-9 | API ↔ CITADEL | HTTPS + HMAC-SHA256 body signature | `CYBERPATH_CITADEL_KEY_SECRET` |
| TB-10 | API ↔ NIS2 Compass | HTTPS bearer (Compass is caller) | sdk auth middleware on inbound |
| TB-11 | API ↔ IRFlow webhook | HTTPS + HMAC-SHA256 (inbound) | `CYBERPATH_IRFLOW_KEY_SECRET` |
| TB-12 | Content registry ↔ API | Bearer token + signature on lab images | Cosign verify on lab-image pull (see `image-signing.md`) |
| TB-13 | Tenant A ↔ Tenant B | Logical, enforced in app | `tenant_id` row-level filter on every query; integration test (see `pre-audit-plan.md`) |

### 3. Data classification

| Class | Examples | Storage rule |
|---|---|---|
| Public | Track metadata, lesson outlines (Apache 2.0 licensed), NIS2 measure mapping | Stored as-is |
| Operational metadata | Lab session ids, resource metrics, completion timestamps, quiz score | Stored — joins to user for audit |
| Learner PII | email, display_name, role, tenant | Stored. GDPR Art. 17 erasure via `user_id` indirection — completion records remain anchored to a now-pseudonymous id |
| Audit-grade evidence | `completions.evidence_hash`, `content_version_id`, `certifications.signature` | Append-only; corrections by follow-on `cyberpath.correction` event, never mutation |
| Secrets | JWT signing key, DB password, CITADEL/IRFlow HMAC, certification Ed25519 private key | K8s Secret, mounted as env vars or KMS-backed reference. Never logged |

Rule: **completions are immutable**. Quiz answers and lesson
content are not stored per-learner beyond what the score requires.
Audit metadata never contains raw user inputs from labs.

### 4. STRIDE per component

#### 4.1 API server (`internal/...`)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| **S**poofing | Forged JWT | sdk verify, issuer check, role allowlist | Secret leak (covered in AT-2) |
| **T**ampering | Mid-flight body modification | TLS at ingress; HMAC for outbound emits | In-cluster MITM if NetworkPolicy off |
| **R**epudiation | Learner denies completing a track | Audit row per state-changing call; CITADEL WORM mirror for completions | Operator-as-DBA can delete app-side audit rows; CITADEL mirror still proves issuance |
| **I**nfo disclosure | Cross-tenant query leak | Row-level `tenant_id` filter; integration test enforces isolation | Bug introduced in new query path — covered by checklist 1.3 |
| **D**oS | Flood, slowloris, mass-session spinup | Per-key token bucket; per-tenant lab-session quota; HTTP timeouts | L7 DDoS still requires upstream WAF |
| **E**oP | Role bypass (learner → instructor) | Role checks on every mutating endpoint; instructor-only routes wrapped | Coarse RBAC — no per-track ACL |

#### 4.2 Wasm sandbox host (Rust, v1.0.0, `rust/sandbox-host/`)

The most security-critical component. A sandbox escape means
host-level execution on the sandbox-host pod and is **CRITICAL**.

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Lab image impersonation | Cosign signature verify on pull; SHA-256 pinned in `labs/labs.yaml` | Compromise of content-team signing identity — see `image-signing.md` |
| T | Wasm module tampering | SHA-256 verified on load; refuse-on-mismatch | Build-time poisoning of `labs.yaml` — caught by code review (2 reviewers) |
| R | Lab action denied by learner | `lab_sessions` row records start/end + resource metrics; lab actions hashed into `evidence_hash` | Learner can dispute scoring; CITADEL row anchors |
| I | Side-channel between cohorts on shared host | Per-session wasmtime instance; no shared memory; cgroup CPU/memory caps | Timing side-channels via cache (Spectre-class) — out of scope per §6 |
| **D** | Memory-bomb / fuel-bomb lab | `Store::set_fuel`, `Memory::grow` cap, wall-clock kill | Adversarial WASM written to maximise within caps |
| **E** | **Sandbox escape — CRITICAL** | (a) wasmtime version pinned; advisory-driven patch SLA; (b) host-function allowlist (no host FS, no host network by default); (c) `cap-std` for any FS reads; (d) seccomp on sandbox-host pod; (e) sandbox-host runs nonroot, RO root FS, drop ALL caps | wasmtime 0-day; kernel CVEs. Mitigated by defence-in-depth (pod-level seccomp gates blast radius) |

Fuzz corpus and unit-test suite for known escape patterns (see
`pre-audit-plan.md` G1) is the load-bearing pre-audit gate.

#### 4.3 Postgres

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Stolen DB creds | K8s Secret + sealed-secrets/Vault; `ssl_mode=require` | Operator with cluster-admin can read Secret |
| T | Tampering with `completions` | App writes only; no UPDATE on `completions`; CITADEL mirror | DBA-level access still able to mutate locally; cross-check with CITADEL detects |
| R | — | CITADEL WORM is the cross-system non-repudiation anchor | — |
| I | Backup exfil | Pod RO; backup pipeline outside scope | Operator backup policy |
| D | Connection exhaustion | `max_open_conns` bound; readiness gates LB | Slow-query attacks |
| E | SQL injection | `pgx` parameterised queries throughout `internal/db/*_store.go` | Reviewer must keep enforcing — see checklist 1.1 |

#### 4.4 CITADEL upstream client

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Forged WORM emit | Outbound HMAC-SHA256 over canonicalised body | Secret rotation 90d |
| T | Replay | Timestamp + correlation ID; CITADEL receiver dedupes by `correlation_id` | Replay window depends on upstream |
| D | Cascade from upstream outage | Circuit breaker + bounded async queue (1000) + 10s drain + on-disk WAL | Buffer overflow drops events with metric |

#### 4.5 NIS2 Compass coverage / recommend (inbound from Compass)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Forged Compass token | Bearer JWT validated via sdk middleware | Token leak — same as TB-2 |
| I | Cross-tenant coverage leak | `coverage/{user_id}` checks tenant of caller and tenant of subject match | Bug in tenancy filter — integration test enforces |
| D | Slow Compass queries stall coverage workers | Per-handler timeout (60s); coverage query indexed on `(user_id, completed_at)` | Pathological audit queries (`as_of` + `include_expired`) — accept |

#### 4.6 IRFlow webhook (inbound)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Forged IRFlow webhook (impersonation) | HMAC-SHA256 verify with `CYBERPATH_IRFLOW_KEY_SECRET`; reject on mismatch; constant-time compare | Secret leak — rotate per `secrets-management.md` |
| T | Replay of recommendation event | Timestamp + nonce; window 5 min | — |
| I | IRFlow leaks incident metadata into recommend response | Recommend response references `gap` only; no incident-id surfaced back to learner | — |

#### 4.7 Content registry / authoring (Module 8)

Content authoring is a content-author trust hierarchy:

| Tier | Identity | What they may publish | Approval |
|---|---|---|---|
| Core | Maintainers (GitHub org member) | First-party tracks under `content/tracks/` | 2-reviewer rule on PR |
| Verified contributor | Allowlisted GitHub identity | Third-party tracks signed via Sigstore Fulcio with their identity | 1 maintainer review + Kyverno verify |
| Community | Anyone | Forked tracks for self-hosted use only — never auto-installed | n/a |

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Malicious instructor pretends to be core | Identity binding on signed lab images (Sigstore `--certificate-identity-regexp` allowlist) | Compromise of an allowlisted identity — rotate via PR removing identity |
| T | Content tamper post-merge | Content ships in signed lab images; `content_version_id` references immutable revision row | Operator pulls unsigned image — Kyverno admission policy refuses |
| I | Malicious markdown XSS in lesson | Content-quality linter (semgrep custom rule) for raw HTML, on-merge; React escapes by default | Operator disables CSP — checklist 1.5 |
| E | Lab YAML with insecure egress allowlist | Linter denies `egress_cidrs: 0.0.0.0/0`; audit log on every egress allowlist change | Manual operator override per-deployment |

#### 4.8 Frontend (web/, React + TypeScript)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| XSS | Reflected/stored from lesson markdown | React framework escaping; `dangerouslySetInnerHTML` forbidden by lint rule (`eslint-plugin-security`); CSP header enforced | If a custom block escapes both layers — content lint catches |
| CSRF | Cross-origin POST | Bearer auth (no cookies on API surface) | If session cookies introduced, need CSRF token |
| Click-jacking | Embedded iframe | `frame-ancestors 'none'` in CSP | — |

### 5. Attack trees — top 4 paths

#### AT-1. Sandbox escape → host RCE on sandbox-host pod (CRITICAL)

```
Goal: Execute attacker-controlled code on the sandbox-host pod;
      from there, attempt lateral movement to API or DB.
└── 1. Author a malicious lab image
    ├── 1.1 Submit as community contribution (rejected by trust tier)
    ├── 1.2 Compromise verified-contributor identity              [low — allowlist + Sigstore audit]
    └── 1.3 Compromise CI signing path (workflow OIDC abuse)      [low — keyless OIDC subject pinned]
└── 2. Image accepted; learner spawns a lab session
└── 3. Wasm guest exploits a wasmtime CVE / host-function bug
    ├── 3.1 Memory corruption in wasmtime (upstream CVE)
    ├── 3.2 Host-function with insufficient input validation
    └── 3.3 Resource cap overflow (fuel underflow on edge case)
└── 4. Achieves arbitrary read/write in sandbox-host process
└── 5. Attempts lateral movement
    └── 5.1 Read API JWT secret from env                          [blocked: NetworkPolicy + sandbox-host has no API secret]
    └── 5.2 Open outbound to attacker C2                          [blocked: egress NetworkPolicy default-deny]
    └── 5.3 Read other learners' session memory                   [blocked: per-session wasmtime instance]
```

Mitigations in place:
- Lab-image signature verification (Cosign, identity-pinned).
- wasmtime version pin + advisory SLA (24h triage / 7d patch for
  Critical, see `disclosure.md`).
- Host-function allowlist; no host filesystem, no host network.
- Per-session isolation; no shared state across sessions.
- Sandbox-host pod: nonroot, RO root FS, drop ALL caps, seccomp
  RuntimeDefault, NetworkPolicy default-deny egress.
- Fuzz corpus for sandbox host functions (`pre-audit-plan.md` G1).

Mitigations missing (gap, tracked in pre-audit-plan):
- Continuous fuzzing infrastructure (one-shot at gap-closure; CI
  integration deferred to v1.1).
- Hardened seccomp profile beyond RuntimeDefault.

#### AT-2. JWT secret leak → forged tokens → bypass RBAC

```
Goal: Mint instructor or admin token offline; access cross-tenant
      data or alter content.
└── 1. Exfiltrate JWT signing secret
    ├── 1.1 Read K8s Secret with cluster-admin                    [moderate]
    ├── 1.2 Compromised CI runner with deploy creds               [moderate]
    └── 1.3 Operator-side leak (env dump, debug log)              [low]
└── 2. Sign JWT with arbitrary claims, including elevated role
└── 3. Call cross-tenant endpoints
    ├── 3.1 Read tenant B coverage                                [blocked: tenant filter]
    ├── 3.2 Issue forged completion via instructor API            [blocked: completions signed by Ed25519 cert key, separate]
    └── 3.3 Inject malicious lab YAML                             [blocked: 2-reviewer rule + Kyverno on signed image]
```

Mitigations in place:
- Dual-secret rotation via opensecstack/sdk.
- Audit row on every authenticated call.
- Tenant isolation enforced at query layer, not at JWT trust.
- Certification signing key is **separate** from JWT signing key —
  forged JWT cannot mint forged certifications.

#### AT-3. Evidence forgery (CRITICAL — undermines NIS2 audit)

```
Goal: Produce a `cyberpath.completion` that an auditor accepts as
      genuine but that the learner did not earn.
└── 1. Compromise certification signing key
    ├── 1.1 Read KMS reference + impersonate KMS caller           [low — KMS bound to pod identity]
    └── 1.2 Steal raw key (KMS bypass)                            [very low — HSM-backed]
└── 2. Or: alter content_version_id after issuance
    └── 2.1 Mutate content_versions row                           [blocked: append-only constraint]
└── 3. Or: replay HMAC-signed CITADEL emit
    └── 3.1 Replay across correlation_id boundary                 [blocked: CITADEL dedupes by correlation_id]
└── 4. Or: submit completion for another user's account
    └── 4.1 Forge JWT (see AT-2) and call /lessons/{id}/complete  [partially blocked: completion endpoint requires authenticated session AND user_id == JWT sub]
```

Mitigations in place:
- Certification signing key in KMS; rotation procedure documented.
- `content_versions` append-only at DB constraint level.
- CITADEL `correlation_id` dedup.
- Cross-system verification: auditor independently re-resolves
  `content_version_id` via public read endpoint and re-hashes
  evidence body.

#### AT-4. Credential stuffing on learner accounts → CSIRT-deployment poisoning

```
Goal: Compromise multiple learner accounts in a national-CSIRT
      multi-tenant deployment to seed false coverage that survives
      until cert expiry.
└── 1. Obtain credential dump from third-party breach
└── 2. Replay against /api/v1/auth/login
    ├── 2.1 No rate limiter                                       [mitigated: per-IP and per-account RL]
    └── 2.2 Argon2id slows offline-only — replay is online        [accept; RL is the control]
└── 3. Account compromised; attacker passes quizzes (or the user
       had already passed); attacker can only see existing record,
       cannot retroactively forge
```

Mitigations in place:
- Argon2id password hashing (opensecstack/sdk).
- Per-account login rate limit + 5-fail lockout window.
- MFA-on-login is on the v1.x roadmap (Track 9 also covers
  user-facing MFA training); pre-audit residual risk.

### 6. Out-of-scope assumptions

- TLS termination correctness is a property of the ingress.
- Cluster-admin-equivalent compromise is out of scope.
- CITADEL upstream and IRFlow consumer/producer security is owned
  by those platforms.
- wasmtime upstream CVEs: CyberPath pins and patches; upstream 0-day
  is residual.
- Hardware side-channels (Spectre/Meltdown class) are out of scope.
- Physical access to nodes is out of scope.
- Quality of community-contributed track content (correctness of
  the cyber-training material itself) — content-quality issue, not
  security advisory.

### 7. Residual risks (accepted)

| Risk | Justification |
|---|---|
| Audit log tampering by DBA | CITADEL WORM mirror provides independent record; cross-check detects on-DB tampering |
| MFA-on-login deferred to v1.x | Argon2id + per-account rate limit + lockout deemed adequate at v1.0; revisit |
| Per-track ACL absent | Coarse RBAC adequate for current roles (learner / instructor / operator / admin); revisit at v2.0 |
| wasmtime 0-day | Patch SLA + defence-in-depth (seccomp, NetworkPolicy) gate blast radius |
| Ed25519 quantum vulnerability | Tracked in ADR-011; v2.0 hybrid ML-DSA migration |
| Spectre-class cross-cohort timing leak | Out of scope per §6; deployers requiring hardware isolation use per-tenant sandbox-host pools |

### 8. Review cadence

Threat model is reviewed quarterly and on every major architecture
change (ADR landing, new external dependency, new endpoint,
wasmtime major upgrade). Owner: CyberPath maintainer rota.

### 9. Related

- `SECURITY.md` — public security policy (four-axis high-level model)
- `docs/security/security-checklist.md` — control evidence matrix
- `docs/security/compliance-map.md` — framework traceability
- `docs/security/image-signing.md` — lab and platform image trust
- `docs/security/pre-audit-plan.md` — gap closures before pentest
- `docs/architecture.md`, `docs/citadel-integration.md`, `docs/nis2-integration.md`
- `../adrs/ADR-012-cyberpath-platform-strategy.md`
- `../adrs/ADR-011-post-quantum-agility.md`
