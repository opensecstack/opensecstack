## CyberPath Security Checklist

CIS-style control matrix. One row per requirement. Status legend:
✓ implemented (target for v1.0.0), ✗ gap, N/A not applicable to
current scope. Evidence cites the v1.0.0 target tree; rows marked
"target" are the implementation contract for the v1.0.0 release.

### 1. Code hardening

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 1.1 | All SQL via parameterised queries | ✓ (target) | `internal/db/*_store.go` (pgx Exec/Query named args) | No `fmt.Sprintf` SQL anywhere. Custom semgrep rule "no raw sql" enforces |
| 1.2 | Input size cap on completion + content endpoints | ✓ (target) | `path.max_input_size`, `content.max_yaml_size` in values.yaml | Enforced in handler |
| 1.3 | JSON parser strictness | ✓ (target) | std `encoding/json`, struct-typed unmarshal | — |
| 1.4 | Tenant isolation at query layer | ✓ (target) | Every query takes `tenant_id` filter; integration test (see `pre-audit-plan.md` G3) | Load-bearing for multi-tenant national CSIRT deployments |
| 1.5 | Output encoding (no HTML rendered server-side) | ✓ (target) | API is JSON-only; React frontend escapes by default; `dangerouslySetInnerHTML` forbidden by `eslint-plugin-security` rule | CSP enforced (row 8.6) |
| 1.6 | Path traversal guards on content YAML loads | ✓ (target) | `filepath.Clean` + base-dir check in `internal/content/loader.go` | Content-quality linter also flags relative `../` |
| 1.7 | Panic recovery emits audit | ✓ (target) | `RecoveryMiddleware` wired in `internal/api/server.go` | — |
| 1.8 | Request timeout | ✓ (target) | chi `middleware.Timeout(60s)` | + per-handler ctx |

### 2. Authentication & Authorisation

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 2.1 | JWT signature verified before any work | ✓ (target) | opensecstack/sdk auth middleware | Same primitives as VertGuard |
| 2.2 | Algorithm allowlist (no `none`) | ✓ (target) | sdk JWT verifier | — |
| 2.3 | Role allowlist on every mutating route | ✓ (target) | `RequireRole`-style wrappers per route | Roles: learner, instructor, operator, admin |
| 2.4 | Cross-tenant query rejected | ✓ (target) | tenant claim ↔ `tenant_id` filter; coverage endpoint additionally checks token tenant matches subject tenant | Integration test in `pre-audit-plan.md` G3 |
| 2.5 | JWT key rotation evidence | ✓ (target) | dual-secret slot via sdk; metric `IncSecretUsed` per slot | Operator runbook includes rotation playbook |
| 2.6 | Sandbox-host gRPC mTLS | ✓ (target) | mTLS within cluster; cert from `cert-manager` | — |
| 2.7 | Per-account login rate limit + lockout | ✓ (target) | sdk rate-limit override on login route; 5-fail / 15-min lockout | MFA on roadmap for v1.x |
| 2.8 | Token TTL bounded | ✓ (target) | `auth.token_ttl=8h` in values.yaml | — |
| 2.9 | Audit precedes auth so 401s are recorded | ✓ (target) | audit MW mounted before auth MW | — |
| 2.10 | Refuse to start with insecure defaults in prod | ✓ (target) | `Config.EnforceProductionGate` (mirrors VertGuard pattern) | Trips on `dev_mode=true`, empty JWT secret, or `db.ssl_mode=disable` when `CYBERPATH_ENV=production` |

### 3. Audit & accountability

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 3.1 | Every state-changing call → audit event | ✓ (target) | audit middleware on POST/PUT/PATCH/DELETE under `/api/v1/` | — |
| 3.2 | Audit row stores actor, role, tenant, action, outcome, request_id, IP | ✓ (target) | `Event` struct + `audit_events` table | `tenant` field load-bearing for multi-tenant audit |
| 3.3 | Audit sink failure does not block request | ✓ (target) | `MultiSink.Record` swallows errors | — |
| 3.4 | Cross-system non-repudiation for completions | ✓ (target) | CITADEL WORM mirror for every `cyberpath.completion` | — |
| 3.5 | Completions immutable from app | ✓ (target) | DAL has no UPDATE on `completions`; corrections via separate `cyberpath.correction` event | DB-level append-only constraint enforced via trigger |
| 3.6 | Audit log fire-test | ✓ (target) | `make audit-fire-test`: writes a test event, fetches from CITADEL via `GET /events?correlation_id=...`, asserts shape | Run pre-release per row 11.4 |

### 4. Cryptography

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 4.1 | JWT HS256 only (sdk default); no `none` | ✓ (target) | sdk JWT verifier | — |
| 4.2 | Webhook signing HMAC-SHA256 (CITADEL, IRFlow) | ✓ (target) | `internal/citadel/client.go`, `internal/irflow/webhook.go` | Same scheme as VertGuard |
| 4.3 | Certification signing Ed25519 from KMS | ✓ (target) | `internal/cert/signer.go` resolves `CYBERPATH_CERT_SIGNING_KEY` to KMS reference | Rotation runbook in `operator-handbook.md` |
| 4.4 | Evidence-body hash BLAKE3 | ✓ (target) | `internal/cert/evidence.go` canonicalises + BLAKE3 | Reproducible by auditor |
| 4.5 | TLS terminated at ingress with modern ciphers | ✓ (assumption) | Operator responsibility | Document in `deployment-helm.md` |
| 4.6 | PQC roadmap | ✓ | `SECURITY.md § Post-quantum strategy`; ADR-011 | Ed25519 vulnerable; v2.0 hybrid ML-DSA |
| 4.7 | Random ID generation | ✓ (target) | `google/uuid` v4 | — |

### 5. Secrets management

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 5.1 | No secrets in repo | ✓ | `.gitignore` + Helm `existingSecret` pattern | — |
| 5.2 | Secret keys mounted via K8s Secret env | ✓ (target) | `templates/deployment.yaml` `secretKeyRef` | — |
| 5.3 | Sealed-secrets / ESO bootstrap audit | ✓ (target) | `docs/secrets-management.md` (lands with v1.0); rotation cadence 90/180-day | Same pattern as VertGuard |
| 5.4 | Certification signing key never leaves KMS | ✓ (target) | `internal/cert/signer.go` calls KMS `Sign`; private key bytes never in process memory | Audit cmd: `make verify-kms-binding` |
| 5.5 | Logs never contain secrets | ✓ (target) | zerolog field-select; secret values not bound to log fields | Manual review |
| 5.6 | HMAC secrets rotated on schedule | ✓ (target) | `secrets-management.md` table; CITADEL + IRFlow keys 90d | — |

### 6. Container & Kubernetes hardening

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 6.1 | Distroless runtime (API) | ✓ (target) | `Dockerfile` (`gcr.io/distroless/base-debian12:nonroot`) | — |
| 6.2 | Non-root | ✓ (target) | UID 65532; `values.yaml` | — |
| 6.3 | Read-only root FS | ✓ (target) | `securityContext.readOnlyRootFilesystem=true` | — |
| 6.4 | Drop ALL capabilities | ✓ (target) | values.yaml | — |
| 6.5 | `allowPrivilegeEscalation=false` | ✓ (target) | values.yaml | — |
| 6.6 | seccomp RuntimeDefault | ✓ (target) | values.yaml | Sandbox-host pod additionally uses a hardened profile |
| 6.7 | NetworkPolicy validated in helm chart | ✓ (target) | `templates/networkpolicy.yaml` + `helm template ... \| kubeconform`; sandbox-host egress default-deny | Verify via `make helm-validate` |
| 6.8 | PodDisruptionBudget | ✓ (target) | values.yaml + `templates/pdb.yaml` | — |
| 6.9 | Resource requests + limits | ✓ (target) | values.yaml | Sandbox-host has tighter caps for fuel/memory budget |
| 6.10 | Liveness + Readiness split | ✓ (target) | `/livez`, `/readyz` | — |
| 6.11 | Image SBOM generated at release | ✓ (target) | `release.yml` syft → CycloneDX → `cosign attest` | See `image-signing.md` |
| 6.12 | Platform images signed (cosign keyless) | ✓ (target) | `.github/workflows/release.yml` cosign sign + attest | See `image-signing.md` |
| 6.13 | Lab images signed; admission policy verifies | ✓ (target) | Kyverno `verify-cyberpath-lab-image` policy with content-author identity allowlist | See `image-signing.md` |

### 7. Dependency hygiene

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 7.1 | `go.sum` checked in | ✓ | repo root | — |
| 7.2 | `Cargo.lock` checked in | ✓ (target) | `rust/` workspace (lands with v1.0) | — |
| 7.3 | `package-lock.json` checked in | ✓ (target) | `web/` | — |
| 7.4 | `go mod tidy` enforced in CI | ✓ (target) | `.github/workflows/ci.yml` | One-line job |
| 7.5 | `govulncheck` in CI | ✓ (target) | `.github/workflows/ci.yml` | PR + push to main + weekly cron |
| 7.6 | `cargo audit` + `cargo geiger` in CI | ✓ (target) | `.github/workflows/ci.yml` | `cargo geiger` quantifies unsafe in sandbox-host |
| 7.7 | `npm audit` + `eslint-plugin-security` in CI | ✓ (target) | `.github/workflows/ci.yml` | — |
| 7.8 | Content-yaml fuzz harness | ✓ (target) | `tests/fuzz/content-yaml/` (`go test -fuzz`) | See `pre-audit-plan.md` G2 |

### 8. Frontend hardening

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 8.1 | TypeScript strict | ✓ (target) | `web/tsconfig.json` | — |
| 8.2 | Generated typed API client | ✓ (target) | OpenAPI → TS client | — |
| 8.3 | `eslint-plugin-security` enabled | ✓ (target) | `web/.eslintrc.json` | — |
| 8.4 | No `dangerouslySetInnerHTML` | ✓ (target) | Lint rule + custom semgrep | Lesson markdown rendered via vetted markdown-it pipeline with HTML disabled |
| 8.5 | xterm.js input bounded | ✓ (target) | `web/src/lab/Terminal.tsx` size cap on send | Anti-DoS for WS |
| 8.6 | CSP header reviewed | ✓ (target) | `default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'` | Reviewed pre-release |
| 8.7 | CORS allowed-origins reviewed | ✓ (target) | `cors.allowed_origins` in values.yaml; default empty (operator must configure) | Pre-release review |

### 9. Logging & observability

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 9.1 | Structured logging (zerolog JSON) | ✓ (target) | `loggerMiddleware` | — |
| 9.2 | Request ID propagation | ✓ (target) | `chi/middleware.RequestID` | Logged + audited |
| 9.3 | No PII in logs | ✓ (target) | Field-select; lesson content + quiz answers never bound | Manual review |
| 9.4 | Prometheus metrics endpoint | ✓ | `/metrics` (unauthenticated, ecosystem convention) | Firewalled in prod |
| 9.5 | Lab session metrics surfaced | ✓ (target) | wasmtime fuel + memory + wall-clock per session | Operator can detect resource-bomb labs |

### 10. Rate limiting & DoS

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 10.1 | Per-key token bucket | ✓ (target) | sdk rate-limit middleware | Key = JWT sub when authed, else IP |
| 10.2 | Per-tenant lab-session quota | ✓ (target) | `lab.max_concurrent_sessions_per_tenant` | Anti-resource-exhaustion in multi-tenant CSIRT deployments |
| 10.3 | Sandbox per-session caps (fuel + memory + wall-clock) | ✓ (target) | wasmtime `Store::set_fuel`, `Memory::grow`, kill at 30 min | Defends against memory-bomb labs |
| 10.4 | Circuit breaker on outbound RPCs | ✓ (target) | `internal/breaker/` (CITADEL, NIS2 Compass, IRFlow) | 5 fails / 30s cooldown |
| 10.5 | Bounded async queue (CITADEL) | ✓ (target) | `AsyncBuffer=1000` default; drop-on-full with metric + on-disk WAL | — |
| 10.6 | 429 with Retry-After | ✓ (target) | sdk rate-limit middleware | — |

### 11. Pre-release security gates

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 11.1 | Code review for sandbox-touching changes | ✓ (target) | CODEOWNERS: `rust/sandbox-host/**` requires 2 reviewers, one from `@opensecstack/security` | Hard rule, not advisory |
| 11.2 | Dependency review on PR | ✓ (target) | `actions/dependency-review-action` on PR | — |
| 11.3 | Sandbox image signature verification (Kyverno) | ✓ (target) | `verify-cyberpath-lab-image` policy in deploy chart | See `image-signing.md` |
| 11.4 | Audit log fire-test | ✓ (target) | `make audit-fire-test` (row 3.6) — pre-release | — |
| 11.5 | Helm NetworkPolicy validated | ✓ (target) | `make helm-validate` (kubeconform + policy lint) | — |
| 11.6 | CSP header review | ✓ (target) | Manual review per release | — |
| 11.7 | CORS allowed-origins review | ✓ (target) | Manual review per release | — |
| 11.8 | Rate-limit review | ✓ (target) | Verify per-route limits and per-tenant quota are wired | — |

### 12. Incident response

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 12.1 | Operator runbook | ✓ (target) | `docs/operator-handbook.md` (lands with v1.0) | Includes sandbox-escape playbook |
| 12.2 | Vulnerability disclosure policy | ✓ | `SECURITY.md` + `docs/security/disclosure.md` | — |
| 12.3 | Coordinated disclosure SLA | ✓ | `disclosure.md` (24h ack / 72h triage / 7d Critical fix) | Sandbox-escape: high-severity by default |
| 12.4 | Tabletop with sandbox-escape scenario | ✗ | Not yet scheduled | Gap — Small (pre-audit-plan T-2 dry-run) |

### Gaps to close before audit

| # | Gap | Cost | Timeline |
|---|---|:-:|---|
| G1 | Sandbox-escape unit test suite (per `pre-audit-plan.md`) | M | T-30d |
| G2 | Content-yaml fuzz campaign | M | T-21d |
| G3 | Multi-tenant integration test | S | T-14d |
| 12.4 | Tabletop with sandbox-escape scenario | S | T-2 weeks (dry-run) |

Cost legend: S = ≤1 day, M = ≤1 week, L = >1 week.

### Related

- `threat-model.md` — architectural threat model
- `pre-audit-plan.md` — gap closure timeline
- `static-analysis.md` — toolchain and CI integration
- `image-signing.md` — trust roots for platform and lab images
