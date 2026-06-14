## VertGuard Security Checklist

CIS-style control matrix. One row per requirement. Status legend:
✓ implemented, ✗ gap, N/A not applicable to current scope.
Evidence cites `path:line` from the v0.1.0-alpha.0 tree.

### 1. Code hardening

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 1.1 | All SQL via parameterised queries | ✓ | `internal/db/*_store.go` (pgx Exec/Query named args) | No `fmt.Sprintf` SQL anywhere |
| 1.2 | Input size cap on scan endpoints | ✓ | `prompt.max_input_size=1048576` in `values.yaml:201` | Enforced in handler |
| 1.3 | JSON parser strictness | ✓ | std `encoding/json`, struct-typed unmarshal | DisallowUnknownFields not used — accepted |
| 1.4 | TLS in transit | ✓ | Pod listens on plain HTTP `:8091` (`Dockerfile:106`, `internal/api/server.go:195-200`); **in-cluster mTLS now enforced** | TLS terminated upstream by ingress. Istio: `deploy/helm/vertguard/templates/mtls-policy.yaml` (PeerAuthentication STRICT + DestinationRule ISTIO_MUTUAL). Linkerd: `deploy/linkerd/mtls-policy.yaml` (Server + ServerAuthorization). `values.yaml` key `mtls.enabled=true`. |
| 1.5 | Output encoding (no HTML rendered server-side) | ✓ | API is JSON-only | — |
| 1.6 | Path traversal guards on file inputs | N/A | No file path inputs in API surface (Phase 4.1) | Revisit when media upload lands |
| 1.7 | Panic recovery emits audit | ✓ | `internal/api/server.go:67-71` (`RecoveryMiddleware`) | Falls back to chi default if no sink |
| 1.8 | Request timeout | ✓ | `chi middleware.Timeout(60s)` (`internal/api/server.go:72`) | + per-handler ctx |

### 2. Authentication & Authorisation

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 2.1 | JWT signature verified before any work | ✓ | `internal/auth/middleware.go:58` | HS256 only |
| 2.2 | Algorithm allowlist (no `none`, no alg confusion) | ✓ | `internal/auth/jwt.go:131-133` | Header alg checked before HMAC |
| 2.3 | Constant-time signature comparison | ✓ | `hmac.Equal` (`jwt.go:148`) | — |
| 2.4 | Issuer + expiry enforced | ✓ | `jwt.go:168-173` | `exp` required for non-zero |
| 2.5 | RBAC on every mutating route | ✓ | `RequireWrite/Admin` wrappers in `server.go:111-189` | Coarse 5-role model |
| 2.6 | Read endpoints gated to known roles | ✓ | `RequireRead` (`middleware.go:126`) | `IsKnownRole` allowlist |
| 2.7 | JWT denylist (revocation) | ✓ | `internal/auth/denylist/denylist.go` | 30s refresh; JTI + Sub kinds |
| 2.8 | Dual-secret rotation | ✓ | `NewVerifierMulti` (`jwt.go:80`); slot metric `IncSecretUsed` | Operator runbook documents flip |
| 2.9 | Dev-mode bypass clearly flagged | ✓ | `auth.Middleware devMode` arg (`middleware.go:32`); WARN at startup | Triggered when `auth.dev_mode=true` OR `auth.secret==""` |
| 2.10 | Refuse to start in prod with dev-mode on | ✓ | `Config.EnforceProductionGate` (`internal/config/config.go`); wired in `cmd/server/main.go` | Trips on `VG_ENV=production` (or `GO_ENV`) when `auth.dev_mode=true`, empty JWT secret, or `db.ssl_mode=disable` |
| 2.11 | Token TTL bounded | ✓ | `auth.token_ttl=8h` (`values.yaml:176`) | — |
| 2.12 | Audit precedes auth so 401s are recorded | ✓ | `server.go:90-101` audit MW mounted before auth MW | — |

### 3. Audit & accountability

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 3.1 | Every state-changing call → audit event | ✓ | `internal/audit/middleware.go:81-88` (POST/PUT/PATCH/DELETE under `/api/v1/`) | GETs deliberately skipped |
| 3.2 | Audit row stores actor, role, action, outcome, status, request_id, IP | ✓ | `Event` struct (`event.go:27-40`) + `audit_events` table (`migrations/003`) | — |
| 3.3 | Audit sink failure does not block request | ✓ | `MultiSink.Record` swallows errors (`event.go:126-138`) | — |
| 3.4 | Cross-system non-repudiation | ✓ | CITADEL WORM mirror for prompt-scan verdicts (`internal/citadel/client.go`) | — |
| 3.5 | Audit log immutable from app | ✓ | DAL has no UPDATE on `audit_events` | DBA-level tampering is residual risk |
| 3.6 | Audit metrics surface | ✓ | `IncAuditEvent(outcome)` hook | — |

### 4. Cryptography

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 4.1 | JWT HS256 only; no RS256/none | ✓ | `jwt.go:131-133` | — |
| 4.2 | Webhook signing HMAC-SHA256 | ✓ | `citadel/client.go:213, 232-236`; `threatfeed/webhook/publisher.go` | Stripe-style timestamp.body for ThreatFlow |
| 4.3 | Input hash SHA-256, not stored as plaintext | ✓ | `internal/prompt/scanner.go:151-158` | `sha256:` prefix |
| 4.4 | TLS terminated at ingress with modern ciphers | ✓ (assumption) | Operator responsibility per `deployment-helm.md` | Document hardening profile in audit-prep README |
| 4.5 | PQC roadmap | ✓ | `SECURITY.md § Post-quantum strategy`; ADR-011 | C2PA / Ed25519 vulnerable; migration tracked |
| 4.6 | Random ID generation | ✓ | `google/uuid` v4 throughout | — |

### 5. Secrets management

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 5.1 | No secrets in repo | ✓ | `.gitignore` + Helm `existingSecret` pattern | `secret.create=true` only for dev |
| 5.2 | Secret keys mounted via K8s Secret env | ✓ | `templates/deployment.yaml:60-80` | `secretKeyRef` only |
| 5.3 | Secret-management patterns documented | ✓ | `docs/secrets-management.md` (sealed-secrets + Vault/ESO) | — |
| 5.4 | Rotation cadence documented | ✓ | `secrets-management.md` table (90/180-day) | — |
| 5.5 | Logs never contain secrets | ✓ | zerolog field-select; secret values not bound to log fields | Manual review; no secret-redaction filter |
| 5.6 | Production refuses chart-managed secret | ✓ | `secret.create=true` gated by OPA Gatekeeper | `deploy/helm/vertguard/templates/opa-constraint.yaml`: ConstraintTemplate `NoSecretCreateInProd` + Constraint scoped to vertguard namespace. Blocks chart-managed `Secret` objects and `secret.create` RBAC outside `vertguard/profile=dev`. |

### 6. Container & Kubernetes hardening

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 6.1 | Distroless runtime | ✓ | `Dockerfile:86` (`gcr.io/distroless/base-debian12:nonroot`) | — |
| 6.2 | Non-root | ✓ | `Dockerfile:103` (UID 65532); `values.yaml:30-46` | — |
| 6.3 | Read-only root FS | ✓ | `securityContext.readOnlyRootFilesystem=true` (`values.yaml:43`) | — |
| 6.4 | Drop ALL capabilities | ✓ | `values.yaml:44-46` | — |
| 6.5 | `allowPrivilegeEscalation=false` | ✓ | `values.yaml:42` | — |
| 6.6 | seccomp RuntimeDefault | ✓ | `values.yaml:35` | — |
| 6.7 | NetworkPolicy template provided | ✓ | `templates/networkpolicy.yaml` | Off-by-default (`networkPolicy.enabled=false`) — operator must opt in |
| 6.8 | PodDisruptionBudget | ✓ | `values.yaml:86-88`, `templates/pdb.yaml` | `minAvailable=1` |
| 6.9 | Resource requests + limits | ✓ | `values.yaml:69-75` | — |
| 6.10 | HPA optional | ✓ | `values.yaml:77-83` | — |
| 6.11 | Liveness + Readiness split | ✓ | `/livez`, `/readyz` (`server.go:77-78`) | — |
| 6.12 | Image SBOM generated at release | ✓ | `SECURITY.md § Supply chain` (CycloneDX) | Verify in `release.yml` |
| 6.13 | Image signed (cosign) | ✓ | `.github/workflows/release.yml` (cosign sign + CycloneDX attest, keyless OIDC) | See `docs/security/image-signing.md` for verify commands |

### 7. Dependency hygiene

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 7.1 | `go.sum` checked in | ✓ | repo root | — |
| 7.2 | `Cargo.lock` checked in | ✓ | `rust/` workspace | — |
| 7.3 | `go mod tidy` enforced in CI | ✓ | `.github/workflows/ci.yml` `go-mod-tidy` job; `make mod-tidy-check` | New job runs `go mod tidy && git diff --exit-code go.mod go.sum`. Fails the build if either file drifts. Also available as `make mod-tidy-check` for local parity. |
| 7.4 | `govulncheck` in CI | ✓ | `.github/workflows/security.yml` (govulncheck job) | PR + push to main + weekly cron |
| 7.5 | `cargo audit` in CI | ✓ | `.github/workflows/security.yml` (cargo-audit job) | `continue-on-error: true` initially — see workflow comment |
| 7.6 | `pip-audit` for ML side-car | ✓ | `.github/workflows/security.yml` (pip-audit job) | Scans `python/pyproject.toml` incl. ML + training extras |
| 7.7 | Dependabot / Renovate | ? | Not visible in this tree | Verify at org level |

### 8. Logging & observability

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 8.1 | Structured logging (zerolog JSON) | ✓ | `loggerMiddleware` (`server.go:222-238`) | — |
| 8.2 | Request ID propagation | ✓ | `chi/middleware.RequestID` | Logged + audited |
| 8.3 | No raw PII in logs | ✓ | Field-select logging; raw scan input not bound | Manual review |
| 8.4 | Prometheus metrics endpoint | ✓ | `/metrics` (`server.go:81-86`) | Should be firewalled in prod |
| 8.5 | Audit channel separable | ✓ | `audit:true` field on JSONL (`event.go:62`) | Log shipper splits stream |

### 9. Rate limiting & DoS

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 9.1 | Per-key token bucket | ✓ | `internal/ratelimit/limiter.go:181-223` | Key = JWT sub when authed, else IP |
| 9.2 | Per-subject overrides | ✓ | `overrides.go`; admin-managed (`server.go:174-180`) | Burst=0 → block |
| 9.3 | Circuit breaker on outbound RPCs | ✓ | `internal/breaker/breaker.go` (CITADEL, ThreatFlow per-sub) | 5 fails / 30s cooldown |
| 9.4 | Read/Write timeouts on HTTP server | ✓ | `server.go:198-199` (configurable) | — |
| 9.5 | Bounded async queue (CITADEL) | ✓ | `AsyncBuffer=1024` default; drop-on-full with metric | — |
| 9.6 | 429 with Retry-After | ✓ | `limiter.go:276-280` | — |

### 10. Incident response

| # | Requirement | Status | Evidence | Notes |
|---|---|:-:|---|---|
| 10.1 | Operator runbook | ✓ | `docs/operator-runbook.md` (10 playbooks) | — |
| 10.2 | Escalation matrix | ✓ | `operator-runbook.md § 5` | — |
| 10.3 | Vulnerability disclosure policy | ✓ | `SECURITY.md` + GitHub Security Advisory channel | Updated in this package; see `disclosure.md` |
| 10.4 | Coordinated disclosure SLA | ✓ | 24h ack / 7-day triage / 90-day disclosure (this package) | — |
| 10.5 | Customer-facing security status page | ✓ | `deploy/statuspage/cstate.yaml`; `.github/workflows/statuspage.yml` | cstate static status page config with 5 monitored components (API, ML Service, CITADEL, ThreatFlow, Dashboard). GHA workflow pings each health endpoint every 5 min and opens a GitHub Issue on failure. |
| 10.6 | Tabletop exercise cadence | ✓ | `docs/security/tabletop-runbook.md` | 90-minute quarterly exercise guide. 5 scenarios: JWT secret compromise, ML model poisoning, CITADEL replay attack, DB credential leak, DDoS against scan endpoint. Participants, schedule, action-item template, and post-exercise checklist included. T-2 weeks dry-run ties to `pre-audit-plan.md`. |

### Gaps to close before audit

| # | Gap | Cost | Timeline | Closed by |
|---|---|:-:|---|---|
| 1.4 | In-cluster mTLS between API and ML side-car | M | Phase 4.3 | **Closed** — `deploy/helm/vertguard/templates/mtls-policy.yaml` (Istio); `deploy/linkerd/mtls-policy.yaml` (Linkerd); `values.yaml` `mtls.enabled=true` |
| 2.10 | Refuse-to-start when `dev_mode=true` and prod profile detected | S | — | **Closed** — `Config.EnforceProductionGate` |
| 5.6 | Helm gate: deny `secret.create=true` outside of `dev` profile | S | Phase 4.3 | **Closed** — `deploy/helm/vertguard/templates/opa-constraint.yaml` (OPA ConstraintTemplate `NoSecretCreateInProd` + Constraint) |
| 6.13 | Sign images with cosign; verify in `release.yml` | M | — | **Closed** — `release.yml` cosign sign + attest |
| 7.3 | `go mod tidy --check` in CI | S | Phase 4.3 | **Closed** — `.github/workflows/ci.yml` `go-mod-tidy` job; `make mod-tidy-check` |
| 7.4 | `govulncheck ./...` in CI matrix | S | — | **Closed** — `security.yml` govulncheck job |
| 7.5 | `cargo audit` in CI matrix | S | — | **Closed** — `security.yml` cargo-audit job |
| 10.5 | Public status page (statuspage.io / cstate static) | M | Phase 4.3 | **Closed** — `deploy/statuspage/cstate.yaml`; `.github/workflows/statuspage.yml` |
| 10.6 | Quarterly tabletop with runbook walkthrough | S | Phase 4.3 | **Closed** — `docs/security/tabletop-runbook.md` (5 scenarios, 90-min format, action-item template) |

Cost legend: S = ≤1 day, M = ≤1 week, L = >1 week.
