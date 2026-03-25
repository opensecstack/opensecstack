# NIS2 Compass — Security Model

This document describes the security architecture of NIS2 Compass: how clients authenticate, how secrets are managed, how the database is hardened, and how the CITADEL WORM audit chain satisfies NIS2 Article 21 requirements. Read this before deploying to any environment accessible from outside localhost.

---

## Authentication

### API Key to JWT Exchange

NIS2 Compass uses a two-step authentication model. A client first presents an API key to obtain a short-lived JWT, then uses that JWT for all subsequent requests.

**Token endpoint:**

```
POST /api/v1/auth/token
Content-Type: application/json

{ "api_key": "<plaintext key>" }
```

On success the response is:

```json
{ "token": "<JWT>", "expires_at": "2026-03-25T14:00:00Z" }
```

The JWT is signed using HS256 with the secret stored in `NIS2_JWT_SECRET`. Token lifetime defaults to 3600 seconds (1 hour) and is configurable via the `NIS2_JWT_TTL` environment variable (integer, seconds).

**Using the token:**

All protected endpoints require the token in the `Authorization` header:

```
Authorization: Bearer <token>
```

The API validates the signature, checks the `exp` claim, and rejects any request where the token is absent, malformed, expired, or signed with a different secret. On any of these conditions the API returns `401 Unauthorized`. Clients must repeat the `POST /api/v1/auth/token` exchange to obtain a new token; there is no token refresh endpoint.

---

## API Key Management

API keys are stored as bcrypt hashes in the database. The plaintext key is generated once at creation time, returned to the caller in the creation response, and never stored or retrievable again. If a key is lost it must be revoked and a new key issued.

Keys carry a scope that controls what operations the bearer may perform:

| Scope | Permitted operations |
|---|---|
| `read` | GET requests only |
| `read_write` | GET, POST, PATCH, DELETE |

Keys can be revoked individually without affecting other keys. Revocation takes effect immediately — any token issued from a revoked key will fail validation on the next request after the key is marked inactive, because the token exchange re-checks key status.

---

## Rate Limiting

The API implements a sliding-window rate limiter backed by Redis. The default limit is 100 requests per minute per source IP address. This is configurable via the `NIS2_RATE_LIMIT` environment variable (integer, requests per minute; see [configuration.md](configuration.md)).

When the limit is exceeded the API returns:

```
HTTP 429 Too Many Requests
Retry-After: <seconds until window resets>
```

Clients should honour the `Retry-After` header and back off accordingly. The limiter uses atomic Redis operations, so correctness is maintained across multiple API replicas sharing the same Redis instance.

---

## Transport Security

The API container does not terminate TLS. TLS must be terminated at the reverse proxy (nginx or Traefik) before traffic reaches port 8090.

### Example nginx TLS termination configuration

```nginx
server {
    listen 80;
    server_name nis2compass.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name nis2compass.example.com;

    ssl_certificate     /etc/ssl/certs/nis2compass.crt;
    ssl_certificate_key /etc/ssl/private/nis2compass.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass         http://localhost:8090;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

The HTTP-to-HTTPS redirect is mandatory in production. Do not expose port 8090 directly to the internet.

---

## Database Security

### Application Role

The `nis2compass` PostgreSQL role is created by `scripts/init-db.sql`, which runs automatically when the `postgres` container initialises. The role is granted login privileges and ownership of the `nis2compass` database but is not a superuser, does not have `CREATEROLE`, and does not have `CREATEDB`. It cannot modify server-level configuration or access other databases on the same cluster.

Grants applied by `init-db.sql`:

- `GRANT ALL PRIVILEGES ON DATABASE nis2compass TO nis2compass`
- `GRANT ALL ON SCHEMA public TO nis2compass`
- `ALTER DEFAULT PRIVILEGES` so future tables and sequences created by migrations are accessible to the role

No direct `GRANT` on individual tables is required because Alembic migrations run as the `nis2compass` role and own the objects they create.

### Authentication Method

PostgreSQL requires password authentication (`md5` or `scram-sha-256` depending on server configuration). The connection string embedded in `NIS2_DB_URL` contains the plaintext password at runtime. This means:

- The `.env` file must never be committed to version control.
- In production, inject `NIS2_DB_PASSWORD` via Docker secrets, a Kubernetes Secret, or a secrets manager rather than a plain `.env` file on disk.
- Connection strings are visible in process environment listings (`/proc/<pid>/environ`) — restrict OS-level access to the container host accordingly.

### Connection String Format

```
postgresql+psycopg2://nis2compass:<NIS2_DB_PASSWORD>@postgres:5432/nis2compass
```

The `postgres` hostname resolves within the Docker `backend` network. In non-Docker deployments substitute the actual host and port.

---

## Secrets Management

### Secrets That Must Never Appear in Version Control

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL superuser (`postgres`) account |
| `NIS2_DB_PASSWORD` | `nis2compass` application database role |
| `REDIS_PASSWORD` | Redis `requirepass` authentication |
| `NIS2_SECRET_KEY` | Flask application secret key (session signing) |
| `NIS2_JWT_SECRET` | HS256 JWT signing secret — minimum 32 characters |

Generate each secret with a cryptographically random source:

```bash
openssl rand -hex 32   # 64-character hex string — suitable for all five secrets
```

### Injection Options

**Docker Compose with `.env` file (minimum viable approach):**

```bash
# Generate and write the file
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 32)
NIS2_DB_PASSWORD=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 32)
NIS2_SECRET_KEY=$(openssl rand -hex 32)
NIS2_JWT_SECRET=$(openssl rand -hex 32)
EOF
chmod 600 .env
```

Add `.env` to `.gitignore` before the first `git add`.

**Docker secrets (recommended for Swarm deployments):**

```bash
openssl rand -hex 32 | docker secret create nis2_jwt_secret -
openssl rand -hex 32 | docker secret create nis2_db_password -
```

Reference secrets in `docker-compose.yml` using the `secrets:` key and mount them as files under `/run/secrets/`. Read the file contents in the application entrypoint.

**Kubernetes Secrets:**

```bash
kubectl create secret generic nis2compass-secrets \
  --from-literal=NIS2_JWT_SECRET=$(openssl rand -hex 32) \
  --from-literal=NIS2_DB_PASSWORD=$(openssl rand -hex 32) \
  --from-literal=REDIS_PASSWORD=$(openssl rand -hex 32) \
  --from-literal=NIS2_SECRET_KEY=$(openssl rand -hex 32)
```

Reference the secret in the Pod spec using `envFrom.secretRef`.

**HashiCorp Vault / AWS Secrets Manager:**

Use a sidecar or init container (e.g., `vault-agent`, `aws-secrets-manager-csi-driver`) to write secrets to a tmpfs volume or inject them as environment variables before the API process starts.

### Rotation Schedule

| Secret | Recommended rotation interval | Notes |
|---|---|---|
| `NIS2_JWT_SECRET` | Quarterly | Rotating invalidates all active JWTs; clients re-authenticate automatically on the next request |
| `NIS2_DB_PASSWORD` | Quarterly | Update in both the secrets store and the `nis2compass` PostgreSQL role simultaneously |
| `REDIS_PASSWORD` | Quarterly | Restart the Redis container and the API container in sequence |
| `NIS2_SECRET_KEY` | On compromise or suspicion of exposure | Rotating invalidates Flask session cookies |
| `POSTGRES_PASSWORD` | Quarterly | Superuser password; update in the secrets store and restart the `postgres` container |

---

## CITADEL WORM Audit Chain

### Overview

Every write operation against the `organisations`, `assessments`, `controls`, and `artifacts` tables appends a row to the `audit_log` table. This log implements the CITADEL WORM (Write-Once Read-Many) pattern: rows can be inserted but never updated or deleted. The chain structure makes any tampering detectable without relying on application-layer controls.

### Row Structure

| Column | Type | Description |
|---|---|---|
| `id` | UUID | Primary key, generated by PostgreSQL (`gen_random_uuid()`) |
| `action` | VARCHAR(100) | Name of the operation, e.g. `assessment_created` |
| `actor` | VARCHAR(255) | Identity of the API key or system process that performed the operation |
| `resource_type` | VARCHAR(100) | Table or logical resource that was changed |
| `resource_id` | UUID | Primary key of the affected row |
| `risk_class` | ENUM | `INFO`, `WARNING`, or `CRITICAL` — severity classification of the event |
| `metadata` | JSONB | Full before/after state of the resource at the time of the action |
| `object_fingerprint` | CHAR(64) | SHA-256 of the canonical JSON serialisation of the resource state |
| `prev_hash` | CHAR(64) | `chain_hash` value of the immediately preceding entry; `NULL` for the genesis entry |
| `chain_hash` | CHAR(64) | SHA-256 of the concatenated fields (see below) |
| `timestamp` | TIMESTAMPTZ | Server time at insertion (`NOW()`) |

### Chain Hash Computation

For the genesis entry (the first row ever inserted):

```
chain_hash = SHA-256(id || action || actor || resource_type || resource_id || "NULL" || timestamp)
```

For all subsequent entries:

```
prev_hash  = chain_hash of the immediately preceding entry (ordered by timestamp)
chain_hash = SHA-256(id || action || actor || resource_type || resource_id || prev_hash || timestamp)
```

The `object_fingerprint` is computed independently:

```
object_fingerprint = SHA-256(canonical_json(full_object_state))
```

where `canonical_json` means keys sorted alphabetically, no insignificant whitespace, and consistent timestamp formatting (ISO 8601 UTC).

### Immutability Enforcement

The PostgreSQL trigger `enforce_audit_log_immutability`, installed by migration `003`, fires `BEFORE UPDATE OR DELETE` on every row of `audit_log`:

```sql
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is immutable: % operations are not permitted', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_audit_log_immutability
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_immutable();
```

This enforcement operates at the database engine level. Any `UPDATE` or `DELETE` against `audit_log` — regardless of which database role issues it, including the `nis2compass` application role — raises an exception and the operation is aborted. Bypassing this constraint requires a superuser (`postgres`) to drop or disable the trigger first; such an action would itself be recorded in PostgreSQL's own server logs (`log_ddl` / `log_min_messages`) and would constitute a separate forensic artifact.

### Chain Integrity Verification

To verify that the audit chain has not been tampered with, walk all entries in ascending timestamp order, recompute `chain_hash` for each entry using the formula above, and compare to the stored value. Any mismatch at position _n_ means the row at position _n_ (or a predecessor) was modified after insertion. A missing row produces a broken `prev_hash` link on the following entry, which is also detectable.

A reference verification script is provided in [audit-log.md](audit-log.md).

### Regulatory Basis

The CITADEL WORM audit chain directly addresses NIS2 Article 21(1), which requires essential and important entities to implement "appropriate and proportionate technical and operational measures" to manage cybersecurity risks. A cryptographically linked, database-enforced immutable audit trail demonstrates that the platform itself is subject to the same accountability standards it helps organisations assess.

---

## Input Validation

All API inputs are validated before any database operation:

- **UUIDs** — path parameters and request body fields carrying identifiers are validated as RFC 4122 UUIDs. Malformed values return `400 Bad Request` before a query is issued.
- **Enum fields** — `status`, `entity_type`, `org_size`, `artifact_type`, `nist_category` are validated against their allowed values. Unknown values return `400`.
- **`measure_ref`** — constrained to single characters `a` through `j` (the ten NIS2 Article 21(2) measures). Values outside this set return `400`.
- **`risk_score`** — constrained to the range 0.0–10.0. Values outside the range return `422`.
- **File uploads** — MIME type is validated against the allowed list for the requested `artifact_type`. File size is bounded by the `NIS2_MAX_UPLOAD_BYTES` environment variable. Files failing either check are rejected before writing to storage.

---

## CORS

In production, restrict `Access-Control-Allow-Origin` to the specific dashboard domain. Wildcard (`*`) is never acceptable in production because it would allow any web origin to make credentialed requests using a stolen JWT.

Example (Flask-CORS configuration):

```python
CORS(app, origins=["https://nis2compass.example.com"], supports_credentials=True)
```

In development, the `NIS2_ENV=development` flag may allow additional origins for local tooling, but this must never reach a production deployment.

---

## Security Headers

The reverse proxy or application middleware should set the following response headers on all API and dashboard responses:

| Header | Recommended value |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'` (tighten as needed for dashboard assets) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

Set `Strict-Transport-Security` at the nginx/Traefik layer after TLS termination, not in the API container, so it is only sent over HTTPS connections.

---

## Known Limitations

**No database-level multi-tenancy isolation.** Row-level security (RLS) on the `organisations`, `assessments`, `controls`, and `artifacts` tables is not yet implemented. All rows are accessible to any authenticated API key with `read` or `read_write` scope. Multi-tenancy at the data layer (restricting key A to organisation X and key B to organisation Y) is tracked as a roadmap item.

**No MFA for dashboard access.** The current authentication model is single-factor (API key). Multi-factor authentication for dashboard users is tracked as a roadmap item. Until MFA is available, enforce strong API key length (minimum 32 random bytes) and rotate keys per the schedule above.
