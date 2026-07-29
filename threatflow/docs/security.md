# ThreatFlow Security Guide

This document covers the operational security configuration for ThreatFlow: authentication, authorization, TLS, secrets management, input validation, rate limiting, network policies, and incident response procedures.

For the threat model and defence-in-depth security controls, see [security-model.md](security-model.md).

---

## Authentication Model

ThreatFlow uses a dual authentication model: JWT Bearer tokens for API consumers and HMAC-SHA256 for the CITADEL connector.

### API Consumers (JWT Bearer Tokens) — Planned v0.2

External API consumers authenticate using short-lived JWT tokens.

**Token exchange:**

```
POST /api/v1/auth/token
Content-Type: application/json

{
  "api_key": "tf-key-abc123..."
}
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt-def456..."
}
```

**Token refresh:**

```
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "rt-def456..."
}
```

**Token usage:**

```
GET /api/v1/iocs
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Token properties:**

| Property | Value |
|----------|-------|
| Algorithm | HS256 (HMAC-SHA256) |
| Expiry | 1 hour |
| Refresh expiry | 24 hours |
| Issuer | `threatflow` |
| Audience | `threatflow-api` |

**Scopes:**

| Scope | Permissions |
|-------|------------|
| `read` | List IOCs, get IOC by ID, list STIX bundles, view correlations |
| `write` | Ingest IOCs, import STIX bundles |
| `admin` | Manage feeds, manage API keys, configure webhooks, all read/write |

### CITADEL Connector (HMAC-SHA256)

ThreatFlow authenticates to CITADEL using HMAC-SHA256 signed requests. See [citadel-integration.md](citadel-integration.md) for full details.

| Header | Value |
|--------|-------|
| `X-CITADEL-KEY` | Connector key ID (from `THREATFLOW_CITADEL_KEY_ID`) |
| `X-CITADEL-TS` | Unix timestamp (seconds) |
| `X-CITADEL-SIG` | `hmac-sha256=<hex(HMAC(secret, key_id:ts:sha256(body)))>` |

**Replay protection:** requests with timestamps older than 5 minutes are rejected. A nonce cache prevents replaying requests within the valid window.

### Webhook Verification (HMAC-SHA256)

Outbound webhooks from ThreatFlow include an HMAC signature for consumer verification.

| Header | Description |
|--------|-------------|
| `X-ThreatFlow-Signature` | `sha256=<hex(HMAC(webhook_secret, raw_body))>` |
| `X-ThreatFlow-Timestamp` | Unix timestamp of the webhook event |

Consumers must verify the signature using timing-safe comparison to prevent timing attacks:

```go
expectedSig := hmac.New(sha256.New, []byte(webhookSecret))
expectedSig.Write(requestBody)
expected := hex.EncodeToString(expectedSig.Sum(nil))

if !hmac.Equal([]byte(receivedSig), []byte(expected)) {
    // Reject request
}
```

---

## Authorization

### Role-Based Access Control

ThreatFlow implements three roles with escalating privileges:

| Role | Permissions |
|------|------------|
| `analyst` | Read IOCs, list feeds, view correlations, export STIX bundles |
| `operator` | All analyst permissions + ingest IOCs, manage feeds, trigger feed polls |
| `admin` | All operator permissions + manage API keys, configure webhooks, manage roles |

Roles are encoded in the JWT `scope` claim and enforced by middleware on every route.

### CITADEL MARSHAL Gating

All mutation operations that modify the IOC store require a MARSHAL EXECUTE decision from CITADEL before proceeding. See [citadel-integration.md](citadel-integration.md) for the full list of MARSHAL-gated operations.

If MARSHAL returns:
- **EXECUTE** — operation proceeds normally
- **REFUSE** — operation is rejected, 403 returned to caller, event WORM-logged
- **HARD_STOP** — all ThreatFlow ingestion is halted (once VIGIL ships — CITADEL v2.0, design-stage as of v1.0.0 — this will also raise a VIGIL RED alert)

---

## TLS Configuration

ThreatFlow listens on plain HTTP internally. TLS must be terminated at the reverse proxy or ingress controller.

### Recommended Configuration

| Connection | Protocol | Configuration |
|-----------|----------|---------------|
| Client to Reverse Proxy | TLS 1.2+ | Terminated at nginx/Traefik/ingress controller |
| Reverse Proxy to ThreatFlow | HTTP | Internal network, port 8091 |
| ThreatFlow to PostgreSQL | TLS | `sslmode=verify-full` in production |
| ThreatFlow to Redis | TLS | `--tls-port 6380` on Redis server |
| ThreatFlow to CITADEL | HTTPS | CITADEL API URL should use `https://` in production |

### Database SSL Mode

Always use `sslmode=verify-full` in production to verify both the server certificate and hostname:

```
THREATFLOW_DB_URL=postgres://threatflow:secret@postgres:5432/threatflow?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.crt
```

| Mode | Security Level | Use Case |
|------|---------------|----------|
| `disable` | None | Local development only |
| `require` | Encrypted, no verification | Minimum for staging |
| `verify-ca` | Encrypted, CA verified | Acceptable for production |
| `verify-full` | Encrypted, CA + hostname verified | Recommended for production |

---

## Secrets Management

### Required Secrets

| Secret | Environment Variable | Purpose |
|--------|---------------------|---------|
| Database password | `THREATFLOW_DB_PASSWORD` (embedded in `THREATFLOW_DB_URL`) | PostgreSQL authentication |
| CITADEL connector key secret | `THREATFLOW_CITADEL_KEY_SECRET` | HMAC signing for CITADEL requests |
| Webhook secret | `THREATFLOW_WEBHOOK_SECRET` | HMAC signing for outbound webhooks |
| JWT signing secret | `THREATFLOW_JWT_SECRET` (planned v0.2) | JWT token generation and validation |
| Redis password | `THREATFLOW_REDIS_PASSWORD` (planned v0.5) | Redis authentication |

### Best Practices

- **NEVER** commit secrets to version control
- **NEVER** log secrets (zerolog is configured to redact known secret fields)
- Use Kubernetes Secrets or HashiCorp Vault for secret injection
- Rotate secrets on a regular schedule (quarterly minimum)
- CITADEL connector keys can be rotated without downtime: register a new key in CITADEL admin, update the ThreatFlow secret, then revoke the old key

### Kubernetes Secrets Example

```bash
kubectl create secret generic threatflow-secrets \
  --namespace opensecstack \
  --from-literal=database-url='postgres://threatflow:SECRET@postgres:5432/threatflow?sslmode=verify-full' \
  --from-literal=citadel-key-id='tf-connector-key' \
  --from-literal=citadel-key-secret='your-hmac-secret' \
  --from-literal=webhook-secret='your-webhook-secret' \
  --from-literal=jwt-secret='your-jwt-secret' \
  --from-literal=redis-password='your-redis-password'
```

### HashiCorp Vault Integration

If using Vault with the Kubernetes auth method:

```yaml
# Vault Agent sidecar annotations
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/role: "threatflow"
vault.hashicorp.com/agent-inject-secret-db: "secret/data/opensecstack/threatflow/database"
vault.hashicorp.com/agent-inject-secret-citadel: "secret/data/opensecstack/threatflow/citadel"
```

---

## Input Validation

### IOC Values

| Validation | Rule |
|-----------|------|
| Control characters | Stripped from all IOC values before processing |
| Maximum length | 500 characters per IOC value |
| Type whitelist | `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file` (hash), `email-addr` |
| Format validation | Each type is validated against its expected format (e.g., IPv4 regex, domain syntax) |

### STIX Bundles

| Validation | Rule |
|-----------|------|
| Maximum bundle size | 10 MB per request |
| Schema validation | All STIX objects validated against STIX 2.1 JSON schema |
| Object type whitelist | Only supported STIX types are accepted (indicator, observed-data, relationship, sighting) |
| Bundle ID format | Must match `bundle--<UUID v4>` pattern |

### SQL Injection Prevention

All database queries use parameterized queries via the `pgx` driver. No raw string concatenation is used in SQL construction:

```go
// Correct: parameterized query
row := db.QueryRow(ctx, "SELECT * FROM iocs WHERE id = $1", iocID)

// Never: string concatenation
// row := db.QueryRow(ctx, "SELECT * FROM iocs WHERE id = '" + iocID + "'")
```

### JSON Injection Prevention

All JSON encoding uses `encoding/json` from the Go standard library. No raw string concatenation is used for JSON construction.

---

## Rate Limiting

Rate limits protect ThreatFlow from abuse and resource exhaustion.

### Default Limits

| Scope | Limit | Description |
|-------|-------|-------------|
| Global (per IP) | 200 req/s | All endpoints combined |
| IOC ingestion (per API key) | 50 req/s | POST `/api/v1/iocs` |
| STIX bundle import (per API key) | 10 req/s | POST `/api/v1/stix/bundles` (large payloads) |
| Authentication | 10 req/min | POST `/api/v1/auth/token` and `/api/v1/auth/refresh` |

### Rate Limit Headers

All responses include standard rate limit headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in the current window |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

When the limit is exceeded, ThreatFlow returns `429 Too Many Requests` with a `Retry-After` header.

---

## Network Security

### Kubernetes NetworkPolicy

Restrict all traffic to and from ThreatFlow pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: threatflow-network-policy
  namespace: opensecstack
spec:
  podSelector:
    matchLabels:
      app: threatflow
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: opensecstack
          podSelector:
            matchLabels:
              app: nginx-ingress
      ports:
        - port: 8091
          protocol: TCP
  egress:
    # PostgreSQL
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - port: 5432
          protocol: TCP
    # Redis
    - to:
        - podSelector:
            matchLabels:
              app: redis
      ports:
        - port: 6379
          protocol: TCP
    # CITADEL
    - to:
        - podSelector:
            matchLabels:
              app: citadel
      ports:
        - port: 8099
          protocol: TCP
    # DNS resolution
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

### Network Access Summary

| Direction | Target | Purpose | Required |
|-----------|--------|---------|----------|
| Inbound | Ingress controller | API traffic | Yes |
| Outbound | PostgreSQL | IOC persistence | Yes |
| Outbound | Redis | Caching (v0.5+) | Optional |
| Outbound | CITADEL | Governance, WORM logging | Optional |
| Outbound | Webhook URLs | Event notifications | Optional |
| Outbound | Internet | Feed polling (TAXII, MISP) | Only if direct; can be proxied |

**No external internet access is required** if feed polling is configured through an internal proxy or feeds are pushed to ThreatFlow via the API.

---

## OWASP API Security Top 10 Mitigations

| Risk | Mitigation |
|------|------------|
| **API1** Broken Object Level Auth | UUID-based resource IDs; ownership and role checks on every resource access |
| **API2** Broken Authentication | JWT with 1-hour expiry; API key rotation; no default credentials |
| **API3** Broken Object Property Auth | Request DTOs with explicit allowed fields; no mass assignment |
| **API4** Unrestricted Resource Consumption | Rate limiting per IP and per API key; 10 MB request size limit |
| **API5** Broken Function Level Auth | Role-based middleware on all route groups; admin routes separated |
| **API6** Unrestricted Access to Sensitive Flows | CITADEL MARSHAL gating on all mutation operations |
| **API7** Server-Side Request Forgery | Allowlisted feed URLs only; no user-controlled URL fetching |
| **API8** Security Misconfiguration | Secure defaults; debug logging disabled in production; no CORS wildcard |
| **API9** Improper Inventory Management | OpenAPI spec versioned with code; all endpoints under `/api/v1/` prefix |
| **API10** Unsafe API Consumption | STIX 2.1 schema validation on all inbound bundles; IOC type whitelist |

---

## Security Headers

ThreatFlow sets the following security headers on all HTTP responses:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Cache-Control` | `no-store` | Prevent caching of sensitive responses |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforce HTTPS (set at reverse proxy) |

---

## Audit Trail

All security-relevant events are WORM-logged to CITADEL:

| Event | Logged Data |
|-------|------------|
| Authentication success | API key ID, IP address, scopes |
| Authentication failure | API key ID (if provided), IP address, reason |
| Authorization failure | User ID, role, requested resource, action |
| Rate limit exceeded | IP address, API key ID, endpoint |
| IOC ingestion | IOC ID, type, value, source, confidence |
| MARSHAL decision | Operation, outcome (EXECUTE/REFUSE/HARD_STOP) |
| Feed configuration change | Feed name, change type, actor |

WORM events are immutable and chain-hashed. They cannot be modified or deleted after emission. See [citadel-integration.md](citadel-integration.md) for the complete event catalogue.

---

## Incident Response

### Security Incident in ThreatFlow

If a security incident is detected within ThreatFlow (e.g., anomalous ingestion patterns, unauthorized access attempts):

1. ThreatFlow automatically creates an incident in **IRFlow** via the integration API
2. The incident includes all relevant WORM log entries from CITADEL
3. The SOC team is notified through IRFlow's escalation workflow

### CITADEL HARD_STOP

When CITADEL issues a HARD_STOP decision:

1. **All ThreatFlow ingestion is immediately halted** — no new IOCs are accepted
2. Feed polling is paused across all sources
3. The admin team must investigate and explicitly resume operations

(Once VIGIL ships — CITADEL v2.0, design-stage as of v1.0.0 — a HARD_STOP will also raise a VIGIL RED alert in CITADEL.)

### Compromised API Key

If an API key is suspected to be compromised:

1. **Immediately revoke** the key in the ThreatFlow admin interface
2. Rotate the CITADEL connector key if the compromised key had admin scope
3. Review the WORM audit trail for unauthorized actions performed with the key
4. Issue new API keys to legitimate consumers
5. Review all IOCs ingested during the compromise window for potential poisoning

### Data Breach Response

If a data breach involving ThreatFlow is confirmed:

1. The CITADEL WORM log provides a complete, immutable audit trail for forensic analysis
2. Determine the scope: which IOCs, feeds, and consumers were accessed
3. Notify affected parties through the NIS2-required notification workflow
4. IRFlow incident tracks the full response timeline
5. Post-incident: rotate all secrets, review access controls, update NetworkPolicies

### Vulnerability Disclosure

Report security vulnerabilities in ThreatFlow to the opensecstack security team. Do not open public issues for security vulnerabilities. See the repository's `SECURITY.md` for the responsible disclosure process.
