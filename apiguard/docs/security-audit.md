# APIGuard v1.0.0 Security Audit Report

## Scope

This audit covers the APIGuard v1.0.0 codebase — all Go and Rust source, Docker images, CI/CD pipeline, and deployment manifests.

---

## Threat Model

### Trust Boundaries

| Boundary | Trust Level | Threat |
|----------|-------------|--------|
| External → API (HTTP) | Untrusted | Injection, DoS, auth bypass, data exfiltration |
| API → PostgreSQL | Trusted internal | SQL injection (mitigated by parameterised queries) |
| API → Redis | Trusted internal | Lua injection (mitigated by predefined scripts) |
| API → CITADEL | Trusted internal | HMAC-signed, replay-protected |
| API → Scan targets | Untrusted external | SSRF, redirect-based credential leak |
| CLI → API | Authenticated | Token theft, misconfigured TLS |

### Attack Surface

| Surface | Exposure | Controls |
|---------|----------|----------|
| REST API (8080) | Public (via ingress) | JWT auth, rate limiting, CORS, input validation |
| Scan target URLs | User-supplied | SSRF prevention (private IP block, scheme whitelist) |
| OpenAPI spec uploads | User-supplied files | Size limit (1 MB), path traversal prevention |
| Docker image | Public registry | Non-root user, minimal Alpine, Trivy scan |
| CI/CD secrets | GitHub Actions | Environment isolation, no secret echo |

---

## Static Analysis Results

### gosec (Go SAST)

| Severity | Count | Details |
|----------|-------|---------|
| HIGH | 0 | No high-severity findings |
| MEDIUM | 0 | No medium findings after remediation |
| LOW | 2 | G104 (unhandled error in defer) — accepted risk |

### govulncheck

| Status | Details |
|--------|---------|
| PASS | No known vulnerabilities in Go dependencies |

### cargo audit (Rust parser)

| Status | Details |
|--------|---------|
| PASS | No known vulnerabilities in Rust dependencies |

### Trivy (container image)

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 (Alpine 3.19 base) |

---

## Authentication & Authorization

| Control | Status | Notes |
|---------|--------|-------|
| JWT HMAC-SHA256 validation | PASS | Constant-time comparison, exp/iat/nbf/iss/aud/typ claims verified |
| Secret rotation (dual secret) | PASS | `JWTAuthWithRotation` supports previous + current secret simultaneously |
| API key hashing | PASS | SHA-256 hashed at rest, plaintext returned only on creation |
| Rate limiting (auth endpoints) | PASS | 20 req/min per IP on `/auth/token` |
| Token expiry enforcement | PASS | Default 1h, configurable |
| Replay protection | N/A | JWT is stateless; revocation via short expiry + refresh token |

---

## Input Validation

| Input | Validation | Status |
|-------|-----------|--------|
| Scan target URL | Scheme whitelist (http/https), host resolution check | PASS |
| SSRF prevention | Private IP ranges blocked (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) | PASS |
| Spec upload path | `filepath.Clean` + directory allowlist, no `..` traversal | PASS |
| Request body size | 1 MB limit on all mutation endpoints | PASS |
| JSON Content-Type | `RequireJSONContentType` middleware on all mutation routes | PASS |
| Query params (severity, status) | Whitelist validation before DB query | PASS |
| UUID params | `uuid.Parse` with 400 on invalid format | PASS |

---

## Transport Security

| Control | Status | Notes |
|---------|--------|-------|
| TLS termination | PASS | Via nginx/ingress, documented in operator handbook |
| Redirect following disabled | PASS | `redirect: "error"` on outbound scan requests |
| Security headers | PASS | X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy |
| CORS | PASS | Exact-match origin whitelist, no wildcards |
| HSTS | RECOMMENDED | Should be configured at reverse proxy layer |

---

## Data Protection

| Data | At Rest | In Transit | Notes |
|------|---------|------------|-------|
| Scan findings | PostgreSQL (encrypted disk recommended) | TLS | No PII in findings |
| API keys | SHA-256 hashed | TLS | Plaintext never stored |
| JWT secrets | Environment variable | N/A | Never logged or serialised |
| CITADEL HMAC secret | Environment variable | N/A | Never logged |
| Audit log | PostgreSQL + CITADEL WORM chain | HMAC-signed | Immutable after write |

---

## SBOM (Software Bill of Materials)

Generated via `syft` in the release workflow (`release.yml`):

- Format: SPDX 2.3 JSON
- Attached to container images via `cosign attest`
- Available as GitHub Release artifacts

---

## Recommendations

| Priority | Recommendation | Status |
|----------|---------------|--------|
| HIGH | Deep health check (DB + Redis ping) | Implemented in v1.0.0 |
| MEDIUM | Add `Strict-Transport-Security` header at proxy | Documented |
| MEDIUM | Implement API key scope enforcement (read-only vs full) | Planned for v1.1.0 |
| LOW | Add request ID correlation to all error responses | Already implemented (X-Request-ID) |
| LOW | Consider certificate pinning for CITADEL HMAC connections | Not required for internal network |

---

## Compliance

| Framework | Coverage |
|-----------|----------|
| OWASP API Security Top 10 | Full (A1–A10 scanner modules) |
| NIS2 Article 21(2)(e) | Network security controls documented |
| NIS2 Article 21(2)(h) | Cryptographic controls (SHA-256, HMAC, Ed25519) |
| CWE Top 25 | Input validation covers CWE-79, CWE-89, CWE-918 (SSRF), CWE-22 (path traversal) |
