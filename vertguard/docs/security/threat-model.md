## VertGuard Threat Model

STRIDE-lite + attack-tree analysis for the VertGuard AI-attack defence
platform (v0.1.0-alpha.0, Phase 4.1–4.3 scope). Companion to `SECURITY.md`
and the per-component implementation files cited inline.

Scope: Go API server, Rust pattern engine, Postgres, CITADEL emit
client, ThreatFlow webhook publisher, dashboard. ML inference
side-car (Phase 4.2) is now integrated. Phase 4.3 adds video stream
handling, audio scoring, and meeting-platform webhook ingestion —
see §10 for the updated threat surface.

### 1. System overview

```
                                  Internet / Operator workstation
                                           │ (TLS-terminated upstream)
                                           ▼
                            ┌──────────────────────────────┐
                            │  Ingress / reverse proxy     │
                            │  (cert-manager + nginx /     │
                            │   ALB / Gateway API)         │
                            └──────────────┬───────────────┘
                                           │ HTTP :8091
                                           ▼
        ┌────────────────────────────────────────────────────────────┐
        │  VertGuard API (Go, distroless nonroot)                    │
        │  ────────────────────────────────────────────────────────  │
        │  RequestID → Logger → Metrics → Recovery → Timeout(60s)    │
        │  /api/v1/* → Audit MW → Auth MW (HS256, denylist) → RL MW  │
        │  Handlers: prompt, phishing, identity, threatfeed, admin   │
        └─────┬──────────────┬──────────────┬──────────────┬─────────┘
              │              │              │              │
              ▼              ▼              ▼              ▼
       ┌────────────┐ ┌─────────────┐ ┌────────────┐ ┌───────────────┐
       │ Rust FFI   │ │ Postgres    │ │ CITADEL    │ │ ThreatFlow    │
       │ patterns + │ │ (audit,     │ │ WORM emit  │ │ webhook fan-  │
       │ c2pa-verify│ │  scans,     │ │ (HMAC-     │ │ out (HMAC-    │
       │            │ │  denylist)  │ │  SHA256)   │ │  SHA256)      │
       └────────────┘ └─────────────┘ └────────────┘ └───────────────┘
                                           │              │
                                           ▼              ▼
                                    upstream WORM     IRFlow / SOC
                                    (immutable)       subscribers
```

### 2. Trust boundaries

| # | Boundary | Crossing | Auth/integrity control |
|---|---|---|---|
| TB-1 | Internet ↔ ingress | TLS terminates upstream; HTTP on 8091 inside cluster | TLS at ingress, NetworkPolicy gates pod ingress |
| TB-2 | Ingress ↔ API | HTTP/JWT | `auth.Middleware` HS256 verify + denylist + rate-limit |
| TB-3 | Operator ↔ admin endpoints | JWT role=admin | `auth.RequireAdmin` (`internal/auth/middleware.go:114`) |
| TB-4 | Tenant operator ↔ scan endpoints | JWT role∈{admin,operator,service} | `auth.RequireWrite` |
| TB-5 | API ↔ Postgres | TCP + password (`ssl_mode=require` in prod values) | DB credentials from K8s Secret, rotated 180d |
| TB-6 | API ↔ CITADEL | HTTPS + HMAC-SHA256 body signature | `internal/citadel/client.go:213` |
| TB-7 | API ↔ ThreatFlow subscribers | HTTPS + HMAC-SHA256 (Stripe-style timestamp.body) | `internal/threatfeed/webhook/publisher.go` |
| TB-8 | API ↔ ML side-car (Phase 4.2) | gRPC over cluster-local network, port 50051 | **mTLS STRICT** — Istio: `deploy/helm/vertguard/templates/mtls-policy.yaml`; Linkerd: `deploy/linkerd/mtls-policy.yaml`. Closes checklist gap 1.4. |
| TB-9 | Dev mode ↔ everything | When `auth.dev_mode=true` or `auth.secret=""` a synthetic admin identity is injected | Startup WARN log; production gate via Helm `config.auth.dev_mode=false` |

### 3. Data classification

| Class | Examples | Storage rule |
|---|---|---|
| Public | IOC catalogue, ATLAS mappings, health, metrics | Stored as-is |
| Operational metadata | scan IDs, classification, confidence, timestamps, request IDs | Stored — joins to actor for audit |
| PII / regulated content | prompt/phishing input text | **Never persisted raw**. SHA-256 hash only (`prompt_scans.input_hash`, `internal/prompt/scanner.go:151-158`). Optional retention (`media.content_retention=true`) requires per-tenant encryption at rest |
| Secrets | JWT signing key, DB password, CITADEL/ThreatFlow HMAC | K8s Secret, mounted as env vars. Never logged (zerolog redaction by field selection) |

Rule: **prompt input is hashed before storage; raw text never persists**.
Audit metadata never contains raw content; only hashes, metadata, and
classification result. See `SECURITY.md § Data handling`.

### 4. STRIDE per component

#### 4.1 API server (`internal/api/server.go`)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| **S**poofing | Forged JWT | HS256 verify, issuer check, role allowlist (`internal/auth/jwt.go:131-176`) | Secret leak (covered in attack tree #2) |
| **T**ampering | Mid-flight body modification | TLS at ingress; HMAC for outbound emits | Sidecar / in-cluster MITM if NetworkPolicy off |
| **R**epudiation | Operator denies action | Audit middleware records every mutating call (`internal/audit/middleware.go`) before reaching handler | Operator-as-DBA can delete `audit_events` rows; mitigated by CITADEL WORM mirror for state-changing flows |
| **I**nfo disclosure | Verbose error leakage | Structured JSON errors with stable codes; recovery middleware emits audit but redacts panic detail | Stack traces in logs (cluster-scoped) |
| **D**oS | Flood, slowloris | `Timeout(60s)`, ReadTimeout/WriteTimeout, per-key token bucket (`internal/ratelimit/limiter.go`) | L7 DDoS still requires upstream WAF |
| **E**oP | Role bypass | `RequireRead/Write/Admin` wrappers per route | Coarse RBAC — no per-resource ACL |

#### 4.2 ML side-car (Phase 4.2, `docs/ml-architecture.md`)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Side-car impersonation | **mTLS STRICT implemented** (ADR-012); `deploy/helm/vertguard/templates/mtls-policy.yaml` (Istio) / `deploy/linkerd/mtls-policy.yaml` (Linkerd) | NetworkPolicy still recommended as defence-in-depth; enable via `networkPolicy.enabled=true` |
| T | Model tampering | SHA-256 checksum on load (`models.yaml`); refusal-on-mismatch | Build-time poisoning of `models.yaml` itself |
| R | — | Inference call audited via parent API audit row | — |
| I | Inference data exfil | No outbound by default (`SECURITY.md § design principles`) | Operator-misconfigured `nemo_endpoint` could leak |
| D | GPU exhaustion | Input size cap, inference budget, parent timeouts | Adversarial prompts pre-cap |
| E | Container escape | Distroless, nonroot, RO root FS, drop ALL caps | Kernel CVEs |

#### 4.3 Postgres

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Stolen DB creds | K8s Secret + sealed-secrets/Vault; `ssl_mode=require` | Operator with cluster-admin can read Secret |
| T | Tampering with audit table | App writes only; audit_events has no UPDATE path in DAL; CITADEL mirror for mutations | DBA-level access still able to mutate |
| R | — | See above; CITADEL WORM is the cross-system non-repudiation anchor | — |
| I | Backup exfil | Pod RO; backup pipeline outside scope of VertGuard | Operator backup policy |
| D | Connection exhaustion | `max_open_conns=25`; readiness probe gates LB | Slow-query attacks |
| E | SQL injection | `pgx` parameterised queries throughout `internal/db/*_store.go` (no string concat) | Reviewer must keep enforcing |

#### 4.4 CITADEL upstream client

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Forged WORM emit | Outbound HMAC-SHA256 over body | Secret rotation 90d (see secrets-management.md) |
| T | Replay | Timestamp + correlation ID; CITADEL receiver enforces dedup | Replay window depends on upstream |
| D | Cascade from upstream outage | Circuit breaker (`internal/breaker/breaker.go`) + bounded async queue + 10s drain on shutdown | Buffer overflow drops events with metric `dropped_buffer_full` |

#### 4.5 ThreatFlow webhook publisher

| Threat | Vector | Control | Residual |
|---|---|---|---|
| S | Subscriber spoofs incoming | Inbound webhook secret (`VERTGUARD_THREATFLOW_WEBHOOK_SECRET`) | — |
| T | Outbound payload tamper | HMAC-SHA256 with timestamp.body (`internal/threatfeed/webhook/publisher.go`) | — |
| D | Slow subscriber stalls fan-out | Per-subscriber breaker, HTTP timeouts | Many slow subs still consume goroutines |

#### 4.6 Dashboard (web/, generated TS client)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| XSS | Reflected/stored | TS client typed against OpenAPI; React framework escaping | CSP not yet hardened (gap, see checklist) |
| CSRF | Cross-origin POST | Bearer auth (no cookies on API surface) | If session cookies introduced, need CSRF token |

### 5. Attack trees — top 3 paths

#### AT-1. Operator account compromise → admin abuse → token denylist mass-add → DoS

```
Goal: Self-DoS via runaway revocation.
└── 1. Compromise operator/admin credentials
    ├── 1.1 Phishing of operator session token            [likely]
    ├── 1.2 Stolen workstation with cached `kubectl` cred [moderate]
    └── 1.3 CI/CD secret leak (admin JWT in pipeline log) [moderate]
└── 2. Use admin role to call POST /api/v1/admin/denylist
    ├── 2.1 Add wildcard sub entries for legitimate users
    └── 2.2 Loop the denylist add via script
└── 3. Cache snapshot grows; auth hot path checks per-claim
        Result: legitimate operators see 401 token_revoked.
```

Mitigations in place:
- Audit row per admin call (`internal/audit/middleware.go`).
- `auth.RequireAdmin` requires admin role (no operator escalation path).
- Cache size metric `SetDenylistSize` — alertable threshold.
- Denylist is reversible (DELETE endpoint).

Mitigations missing (gap):
- No rate cap specifically on denylist mutations (general per-key
  limiter applies but admin keys may have generous overrides).
- No four-eyes / approval gate on denylist additions.

#### AT-2. JWT secret leak → forged tokens → bypass RBAC

```
Goal: Mint admin token offline; full API takeover.
└── 1. Exfiltrate VERTGUARD_AUTH_SECRET
    ├── 1.1 Read K8s Secret with cluster-admin            [moderate]
    ├── 1.2 Compromised CI runner with deploy creds       [moderate]
    └── 1.3 Operator-side leak (env dump, debug log)      [low — zerolog field-select]
└── 2. Sign HS256 JWT with arbitrary claims
└── 3. Call any endpoint as admin
```

Mitigations in place:
- Dual-secret rotation (`NewVerifierMulti`, `internal/auth/jwt.go:80`)
  accepts current + previous, enabling zero-downtime rotation when
  leak is suspected.
- Per-secret-slot metric (`IncSecretUsed`) — observability for stuck
  rotations.
- JWT denylist (`internal/auth/denylist`) — kill specific JTI or
  burn-down all tokens for a sub.
- Audit row records every authenticated call.
- Issuer claim enforcement reduces blast radius if a non-VG token is
  accepted in another system using the same secret.

Residual: until rotation completes, forged tokens remain valid.
Recovery flow: rotate secret → all live tokens invalidated; clients
re-auth.

#### AT-3. Malicious prompt → LLM (downstream of VG) exfiltrates → VG scan emits to CITADEL → contained

```
Goal: Prompt-injection attack on a customer LLM that VG protects;
      ensure VG itself does not become the leak vector.
└── 1. Attacker submits crafted prompt to a customer LLM front-end
└── 2. Front-end forwards prompt to /api/v1/prompt/scan
    └── 2.1 VG classifies CLEAN incorrectly (detection bypass)
        └── 2.1.1 Pattern engine miss
        └── 2.1.2 Threshold misconfigured
└── 3. LLM executes injection; data leaves customer perimeter
└── 4. VG audit row + (if BLOCKED/SUSPICIOUS) WORM evidence emit
```

Mitigations in place:
- Pattern engine versioned, quarterly refresh (see `SECURITY.md`).
- Confidence thresholds configurable (`prompt.clean_threshold`,
  `prompt.block_threshold`).
- Every scan persists `input_hash` + classification + match list →
  retroactive triage possible.
- WORM evidence emitted on positive classification → tamper-evident
  record outside VG itself.
- Adversarial test corpus in `tests/adversarial/` (see SECURITY.md).

Residual: detection bypass is an open research problem. VG reduces
risk, does not eliminate it. Defence-in-depth with downstream
guardrails (NeMo, Llama Guard) is the recommended deployment.

### 10. Phase 4.3 Threat Surface Extensions

#### 10.1 New components

Phase 4.3 introduces three new API surfaces not present in Phase 4.1–4.2:

| Component | Protocol | Entry point | Notes |
|---|---|---|---|
| Video stream handler | WebSocket (bidirectional) | `GET /api/v1/video/stream` (upgrade) | Long-lived connection; receives frames from browser or device client |
| Audio scoring handler | HTTP POST | `POST /api/v1/audio/score` | Accepts raw audio bytes or URL reference; calls Rust audio-fingerprint subprocess |
| Meeting platform webhooks | HTTPS POST | `POST /api/v1/webhooks/meeting` | Receives event payloads from Zoom, Teams, and WebEx; validates HMAC-SHA256 or token signature per vendor |

#### 10.2 New trust boundaries

| # | Boundary | Crossing | Auth/integrity control |
|---|---|---|---|
| TB-10 | Meeting platform → VertGuard webhook | HTTPS POST with vendor signature header | HMAC-SHA256 validated per vendor spec (Zoom: `x-zm-signature`, Teams: Bot Framework auth token, WebEx: shared secret). Timestamp freshness check (±5 min tolerance) to resist replay attacks. |
| TB-11 | Browser WebSocket client → video stream handler | WebSocket upgrade over HTTPS | JWT auth enforced on the HTTP upgrade request (`Authorization: Bearer <token>`) before the connection is upgraded. Subsequent frames are tied to the authenticated session — no re-auth per frame. |
| TB-12 | Rust audio-fingerprint subprocess → Go handler | Local subprocess pipe (stdin/stdout), no network | subprocess is spawned by the Go handler via `exec.Command`; communication is over OS pipes. No network socket; the subprocess cannot initiate outbound connections. IPC input size is capped to match `prompt.max_input_size`. |

#### 10.3 STRIDE for new components

##### Video stream handler (`/api/v1/video/stream`)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| **S**poofing | Unauthenticated WebSocket upgrade | JWT validated on HTTP upgrade before `101 Switching Protocols`; session bound to JWT sub for the connection lifetime | Token replay within TTL if the JWT is stolen (mitigated by denylist) |
| **T**ampering | Frame injection mid-stream | TLS at ingress; WebSocket framing integrity via TLS record layer | Compromised TLS (ingress misconfiguration) could allow frame injection |
| **R**epudiation | Attacker denies submitting a frame | Each stream session has a request ID + actor sub. Frame-level audit is impractical at volume; session-open and session-close events are audited. | Mid-session content not individually audited; audit granularity is session-level |
| **I**nfo disclosure | Stream content exfiltrated via verbose error or log | Frame content not logged; errors return stable codes. `RecoveryMiddleware` redacts panic detail. | Video frame bytes in memory; kernel memory disclosure (Spectre-class) is out of scope |
| **D**oS | Persistent WebSocket connections exhaust goroutine pool | Connection timeout enforced; max concurrent WebSocket connections configurable; per-subject rate limit applies to upgrade requests | Long-lived connections with slow-sending clients can still hold goroutines |
| **E**oP | Attacker upgrades to WebSocket then pivots to non-video endpoints | WebSocket handler is scoped to video routes only; standard `RequireWrite` gate on upgrade | — |

##### Audio scoring handler (`POST /api/v1/audio/score`)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| **S**poofing | Forged JWT claiming elevated role | Standard `auth.Middleware` HS256 verify + `RequireWrite` | Same as API surface baseline |
| **T**ampering | Malicious audio bytes → subprocess escape | Subprocess invoked via `exec.Command` with sanitised args; stdin is the only input channel; subprocess runs as nonroot in distroless | Adversarial audio crafted to exploit parser vulnerabilities in the Rust fingerprint library |
| **R**epudiation | Operator denies submitting audio for analysis | Audit middleware records POST /api/v1/audio/score; `input_hash` (SHA-256 of audio bytes) stored, not raw bytes | — |
| **I**nfo disclosure | Audio content retained beyond the request | Audio bytes not persisted; only SHA-256 hash stored (same pattern as prompt scans) | Memory residual within the process lifetime |
| **D**oS | Large audio file exhausts memory / CPU | Input size cap enforced at the handler level (same `max_input_size` as prompt); subprocess killed on parent timeout | Adversarial audio designed to maximise decode time below the size cap |
| **E**oP | Subprocess escape → host access | Distroless nonroot container; RO root FS; drop ALL capabilities; seccomp RuntimeDefault | Kernel CVEs allowing container escape |

##### Meeting platform webhooks (`POST /api/v1/webhooks/meeting`)

| Threat | Vector | Control | Residual |
|---|---|---|---|
| **S**poofing | Forged webhook payload impersonating Zoom/Teams/WebEx | HMAC-SHA256 (or vendor token) validated before any processing; timestamp freshness check (±5 min) per TB-10 | Timing attack on the HMAC comparison — mitigated by `hmac.Equal` constant-time comparison (same pattern as `citadel/client.go:232-236`) |
| **T**ampering | Body modified in transit | TLS at ingress; HMAC covers the full body; any modification invalidates the signature | HMAC secret leaked (see AT-5 below) |
| **R**epudiation | Meeting platform denies sending event | Webhook events logged with signature-verified flag and correlation ID; CITADEL WORM emit for state-changing meeting events | Meeting platform's own audit trail is the primary record; VertGuard is a consumer |
| **I**nfo disclosure | Meeting metadata (participant IDs, meeting titles) in logs | Event metadata subject to same field-select logging discipline as prompt data; meeting content not logged | Operator misconfiguration of log verbosity |
| **D**oS | Webhook flood from platform or spoofed source | Per-IP and per-platform-account rate limits; invalid HMAC payloads rejected before any processing | Platform-side flood cannot be distinguished from legitimate high-volume events without platform-side rate caps |
| **E**oP | Webhook handler has broader permissions than necessary | Handler scoped to webhook-specific processing; no admin actions triggered by webhook payload alone | Logic vulnerabilities in the event handler if webhook payload is used to drive RBAC decisions |

#### 10.4 New attack trees

##### AT-4 — Adversarial CLIP embedding injection (evade GAN detector)

```
Goal: Craft a video frame or image whose CLIP feature vector causes
      the GAN detector to score CLEAN, bypassing VertGuard detection.

└── 1. Attacker studies the public CLIP embedding space
    ├── 1.1 Query VertGuard API with probe inputs to infer confidence scores   [possible — API is accessible]
    ├── 1.2 Use open-source CLIP model (same weights as VertGuard's pin) to
    │       compute embeddings offline                                          [likely — model is public]
    └── 1.3 Read published adversarial ML literature on CLIP perturbation      [freely available]

└── 2. Attacker optimises a perturbation
    ├── 2.1 White-box: use gradient descent against the local CLIP model
    │       to craft a minimal-perturbation feature vector that maps to
    │       a known-clean region of the embedding space                        [technically feasible]
    └── 2.2 Black-box: iterative query attack against the VertGuard API
             using confidence scores as the signal (if exposed)               [rate-limited but possible over time]

└── 3. Attacker submits perturbed input
    └── 3.1 POST /api/v1/video/stream or /api/v1/audio/score (Phase 4.3)
        └── 3.1.1 GAN detector returns CLEAN
            └── 3.1.2 Malicious content reaches downstream LLM / user
```

Mitigations in place:
- SHA-256 `input_hash` enables retroactive triage when new detection rules
  are deployed — re-scan historical hashes.
- Adversarial test corpus (`tests/adversarial/`) includes CLIP perturbation
  samples from published research; updated quarterly.
- Confidence scores are not surfaced to unauthenticated callers; black-box
  query attacks require valid JWT.
- Per-subject rate limits slow iterative query attacks.

Mitigations missing (accepted residual):
- Detection bypass is an open research problem. VertGuard reduces risk via
  depth-of-defence (pattern engine + ML); it does not guarantee detection.
- Ensemble voting across multiple detectors (planned for v0.2) would raise
  the bar for simultaneous bypass across all models.

##### AT-5 — Meeting webhook spoofing via HMAC timing attack or secret leak

```
Goal: Forge a meeting platform webhook event to inject a fraudulent
      action into VertGuard's meeting pipeline.

└── 1a. Timing attack path
    ├── 1a.1 Attacker sends crafted webhook with controlled body      [possible if on same network]
    └── 1a.2 Measures response time variation to infer partial HMAC   [mitigated by constant-time comparison]

└── 1b. Secret leak path
    ├── 1b.1 Meeting platform webhook secret exposed in CI log        [same vector as AT-2 for JWT]
    ├── 1b.2 K8s Secret read by cluster-admin                         [moderate — same risk tier as JWT secret]
    └── 1b.3 Vendor-side leak (Zoom/Teams/WebEx secret management)    [out of scope — vendor risk]

└── 2. Attacker crafts and signs a forged event
    ├── 2.1 Fabricate participant-join or recording-available event
    └── 2.2 Sign with leaked secret using HMAC-SHA256

└── 3. VertGuard accepts the forged event
    └── 3.1 Handler processes fake event data
        └── 3.1.1 Downstream actions triggered (scan, audit row, WORM emit)
                  based on attacker-controlled payload
```

Mitigations in place:
- `hmac.Equal` constant-time comparison (same pattern as `citadel/client.go:232-236`)
  closes the timing attack path.
- Timestamp freshness check (±5 min) prevents simple replay of stolen
  signatures even if the body is unchanged.
- Webhook secret is a K8s Secret (`VERTGUARD_MEETING_WEBHOOK_SECRET`),
  not hardcoded; same rotation cadence as CITADEL HMAC (90d).
- WORM emit for state-changing meeting events provides an independent
  tamper-evident record to detect fraudulent injections retroactively.

Mitigations missing (accepted residual):
- If the vendor-side secret is compromised (Zoom/Teams/WebEx manages it),
  VertGuard cannot detect the forgery at the signature layer. Defence:
  payload validation (expected schema, participant IDs from allowlist)
  as a secondary gate.
- No four-eyes gate on meeting-triggered actions; a forged event that passes
  HMAC would be processed automatically.

### 6. Out-of-scope assumptions

- TLS termination correctness is a property of the ingress, not VG.
- Cluster-admin-equivalent compromise (etcd, kubelet) is out of
  scope — VG cannot defend against an attacker who can read all
  Secrets and exec into pods.
- CITADEL upstream and ThreatFlow consumer security is owned by
  those platforms (see their respective SECURITY.md).
- HuggingFace model supply-chain attacks: VG verifies SHA-256 of the
  binary it loads. Upstream poisoning before our pinning is an
  ecosystem concern.
- Hardware side-channels (Spectre/Meltdown class) are out of scope.
- Physical access to nodes is out of scope.

### 7. Residual risks (accepted)

| Risk | Justification |
|---|---|
| Audit log tampering by DBA | CITADEL WORM mirror provides independent record; on-DB tampering is detectable via cross-check |
| `auth.dev_mode=true` accidentally in prod | Startup WARN + Helm default `false` + checklist gate; further hardening (refuse-to-start when DevMode + prod context) is a tracked gap |
| Per-resource ACL absent | Coarse RBAC adequate for current 5-role model; revisit at v1.0 if multi-tenant requirements firm up |
| Memory bucket cardinality explosion in rate limiter | Janitor evicts after `IdleTTL=10m`; cap-by-key is a v0.2 enhancement |
| C2PA / Ed25519 quantum vulnerability | Tracked in ADR-011; migration mirrors upstream C2PA PQ adoption |

### 8. Review cadence

Threat model is reviewed quarterly and on every major architecture
change (ADR landing, new external dependency, new endpoint).
Owner: VertGuard maintainer rota.

### 9. Related

- `SECURITY.md` — public security policy
- `docs/security/security-checklist.md` — control evidence matrix
- `docs/security/compliance-map.md` — framework traceability
- `docs/security/tabletop-runbook.md` — quarterly tabletop exercise guide (5 scenarios)
- `adrs/ADR-012-ml-inference-architecture.md`
- `../adrs/ADR-010-vertguard-platform-strategy.md`
- `../adrs/ADR-011-post-quantum-agility.md`
