# APIGuard Security Reference

APIGuard is a security tool. This document describes its own security model — how it protects itself, its users, and the systems it scans.

---

## Trust Model

| Actor | Trust Level | Notes |
|-------|------------|-------|
| Authenticated API users | Trusted within their scope | JWT or API key verified on every request |
| CLI invocation | Untrusted input | All paths, URLs, and flags sanitised before use |
| OpenAPI/Swagger schema files | Untrusted | Parsed by Rust parser in isolated subprocess |
| Target API responses | Untrusted | Analysed by Rust response analyser — no eval, no exec |
| Database | Trusted | Only accessible from the application layer |
| CITADEL webhook receiver | Trusted after signature verification | HMAC-SHA256 on every event |

---

## Authentication

### JWT

All API endpoints require a valid JWT in the `Authorization: Bearer <token>` header. Tokens are:

- Signed with HMAC-SHA256 using `APIGUARD_JWT_SECRET`
- Short-lived (default: 1 hour access token, 7 days refresh token)
- Verified on every request — expiry, issuer, audience checked

The JWT secret must be at least 32 bytes. APIGuard logs a warning on startup if the secret is missing or too short.

### API Keys

API keys are an alternative to JWT for machine-to-machine access (CI/CD pipelines, integrations).

- Stored as SHA-256 hash — the plaintext is never stored
- Scoped: each key has a `scope` field limiting which endpoints it can access
- Revocable at any time via `DELETE /api/v1/api-keys/{id}`

### Rate Limiting

All endpoints are rate-limited using a Redis-backed sliding window counter. Default: 100 requests per minute per IP. Exceeding the limit returns HTTP 429 with a `Retry-After` header.

Scan job creation is rate-limited separately to prevent abuse: 10 scans per minute per user by default.

---

## Input Validation

| Input | Validation |
|-------|-----------|
| OpenAPI spec (URL) | URL scheme whitelist (https only in production), max size 10 MB |
| OpenAPI spec (file upload) | Size limit, MIME type check, Rust parser in subprocess |
| Target URL | Scheme whitelist, private IP range blocking (unless explicitly allowed) |
| JWT claims | Issuer, audience, expiry, signature — all verified |
| API key | Length, charset, hash comparison — constant-time |
| Pagination parameters | Min/max bounds enforced |
| JSON request bodies | Strict schema validation, max body size 1 MB |

### SSRF Prevention

The scanner's HTTP client is restricted to the configured `target` URL. It cannot be redirected to internal addresses. Private IP ranges (RFC 1918, loopback, link-local) are blocked by default unless `scanner.allow_private_targets: true` is explicitly set.

---

## Secrets Management

- All secrets are read from environment variables, never from config files checked into version control
- The `.env.example` file contains no real secrets — only variable names
- Secrets in memory are zeroed after use where Go permits (JWT secret, OAuth2 client secret)
- API keys are hashed on creation — the server never holds the plaintext after the create response

### Required Secrets

| Secret | Environment Variable | Notes |
|--------|---------------------|-------|
| JWT signing key | `APIGUARD_JWT_SECRET` | Min 32 bytes. Use a random 64-byte value in production. |
| Database password | Part of `APIGUARD_DB_URL` | Use a dedicated database user |
| Redis password | Part of `APIGUARD_REDIS_URL` | Optional for internal Redis |
| CITADEL connector secret | `APIGUARD_CITADEL_KEY_SECRET` (with `APIGUARD_CITADEL_KEY_ID`) | HMAC-SHA256 connector auth. Only required if `APIGUARD_CITADEL_URL` is set. |

---

## Transport Security

- APIGuard does not terminate TLS. Deploy behind a TLS-terminating reverse proxy.
- All outbound connections from APIGuard (to the target API, to CITADEL, to other integrations) verify TLS by default. Never set `tls_skip_verify: true` in production.
- Database connections must use `sslmode=require` or higher in production.

---

## PostgreSQL Security

- APIGuard's database user should have only the permissions it needs: `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the `apiguard` schema.
- The dashboard user should be a separate read-only PostgreSQL user.
- Row-level security can be enabled for multi-tenant deployments.

```sql
-- Minimal production permissions
GRANT CONNECT ON DATABASE apiguard TO apiguard_app;
GRANT USAGE ON SCHEMA public TO apiguard_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO apiguard_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO apiguard_app;
```

---

## Network Isolation

Recommended network topology:

```
Internet
    │
    ▼
[Load Balancer / TLS termination]
    │
    ▼
[APIGuard instances]  ←──────── Internal only
    │           │
    ▼           ▼
[PostgreSQL]  [Redis]   ←──── No external access
```

The target API must be reachable from the APIGuard instances. If scanning a production API, consider running the scanner from within the same VPC/network segment to avoid routing scan traffic over the public internet.

---

## Supply Chain Security

- Dependencies are pinned in `go.sum` (Go) and `Cargo.lock` (Rust)
- An SBOM (`SBOM.json`) is published with each release in CycloneDX format
- Container images are scanned with Trivy on every CI build
- The release workflow signs release artefacts with Sigstore/cosign

---

## Vulnerability Disclosure

To report a security vulnerability in APIGuard:

1. Do **not** open a public GitHub issue
2. Use GitHub Security Advisories: `https://github.com/opensecstack/apiguard/security/advisories/new`
3. Include: description, affected version, reproduction steps, impact assessment
4. Response SLA: acknowledge within 48 hours, patch within 14 days for CRITICAL/HIGH

See [SECURITY.md](../SECURITY.md) for the full disclosure policy.
