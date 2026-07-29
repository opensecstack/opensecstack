# CyberPath Multi-Tenancy (design doc — NOT YET IMPLEMENTED)

> **Status: design document, not shipped functionality.** Everything
> below this notice — RLS policies, the `POST /api/v1/admin/tenants`
> API, the `cyberpath-cli tenant` command family, rate-limit profiles,
> quotas, branding overrides, and the offboarding/GDPR-erase tooling —
> describes a **target design for a future multi-tenancy feature that
> does not exist in the codebase today**.
>
> What actually ships in v1.0.0: a bare `tenant_id UUID` column on
> `users`, `cohorts`, `lab_sessions`, `audit_events`, `webhooks`, and
> the `outbox` table (see `internal/db/migrations/0001_initial.sql`
> and `0002`–`0004`), plus a `tenants` table holding `id`, `slug`,
> `name`, `created_at`, `updated_at`. There is **no** row-level
> security enabled on any table, **no** `/api/v1/admin/tenants` route
> in `internal/api/server.go`, and **no** `tenant` subcommand in
> `cyberpath-cli`. In practice CyberPath runs as a single-tenant
> deployment today.
>
> Treat every code sample, CLI invocation, and API call below as
> **proposed**, not documentation of current behaviour. This content
> is kept because it has real design value for whoever implements real
> multi-tenancy — read it as a plan, not a manual.

Design and operational reference for CyberPath's multi-tenant model.
This document covers the isolation model, tenant provisioning, per-tenant
configuration, cross-tenant data guarantees, offboarding, and the
distinction between platform-admin and tenant-admin roles.

For schema details of the `tenants` table and FK cascade rules, see
[data-model.md](data-model.md). For the brief operator onboarding
checklist, see [operator-handbook.md](operator-handbook.md).

> Status: v1.0.0 ships a single default tenant. The row-level isolation
> model described here is a proposed future upgrade; per-schema
> isolation is a further-out v1.1+ idea. Neither is implemented yet.

---

## Isolation model (proposed — not implemented)

### v1.0.0 — single tenant (actual, current behaviour)

v1.0.0 is deployed with one `tenants` row (the default tenant). All
users, cohorts, and content belong to this tenant. The schema column
`tenant_id` is present on `users`, `cohorts`, and `webhooks` from the
initial migration, which means a future row-level isolation upgrade
can be schema-additive rather than a structural change — but that
upgrade has not been built.

### Proposed — row-level security (RLS)

Every tenant-scoped table enforces row-level security via PostgreSQL RLS
policies. The application connects as the `cyberpath` role; each request
sets a session variable carrying the resolved tenant ID before issuing
any query:

```sql
SET LOCAL app.tenant_id = '<uuid>';
```

RLS policies on tenant-scoped tables:

```sql
-- Example for users
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

Tables that carry `tenant_id` and are covered by RLS policies:

| Table | Isolation column |
|---|---|
| `users` | `tenant_id` |
| `cohorts` | `tenant_id` |
| `webhooks` | `tenant_id` |

Tables that are **not** tenant-scoped (shared across all tenants):

| Table | Reason |
|---|---|
| `tracks` | Content catalogue is platform-wide; per-tenant visibility is controlled by `track_visibility` (v1.1+) |
| `modules`, `lessons`, `content_versions` | Owned by tracks; shared read |
| `lab_definitions` | OCI image catalogue; shared |
| `roles` | Platform role catalogue |

Tables that are indirectly tenant-scoped (tenant is resolved through
the user or cohort FK):

| Table | Scoped via |
|---|---|
| `progress` | `user_id → users.tenant_id` |
| `completions` | `user_id → users.tenant_id` |
| `certifications` | `user_id → users.tenant_id` |
| `lab_sessions` | `user_id → users.tenant_id` |
| `cohort_enrollments` | `cohort_id → cohorts.tenant_id` |
| `audit_events` | `actor` (JWT `sub`) resolved to a tenant at middleware layer |

### v1.1+ — per-schema isolation (planned)

v1.1 will introduce an opt-in per-schema mode where each tenant's data
lives in a dedicated PostgreSQL schema (`tenant_<slug>`). RLS remains as
the default for new tenants; per-schema is available for tenants that
require hard schema-level separation. Migration from row-level to
per-schema is a data-move operation; tooling will be documented in the
v1.1 migration guide.

---

## Tenant provisioning

### Creating a tenant

Tenants are created by a platform admin via the admin API or
`cyberpath-cli`. The slug must match `/^[a-z][a-z0-9-]{2,40}$/`.

```bash
cyberpath-cli tenant create \
    --slug "acme-corp" \
    --display-name "Acme Corporation" \
    --rate-limit-profile medium \
    --citadel-project-id "acme-corp-2027"
```

This inserts a row into `tenants` and initialises the per-tenant
configuration record (see [Per-tenant configuration](#per-tenant-configuration)).

API equivalent:

```http
POST /api/v1/admin/tenants
Authorization: Bearer <platform-admin-token>
Content-Type: application/json

{
  "slug": "acme-corp",
  "display_name": "Acme Corporation",
  "rate_limit_profile": "medium",
  "citadel_project_id": "acme-corp-2027"
}
```

Response:

```json
{
  "id": "b3f1c2d4-...",
  "slug": "acme-corp",
  "display_name": "Acme Corporation",
  "created_at": "2027-03-01T09:00:00Z"
}
```

### Provisioning a tenant-scoped JWT

CyberPath delegates identity to the `opensecstack/sdk` auth tier. After
creating the tenant row, request a tenant-scoped service token from the
ecosystem auth admin. The token must carry:

```json
{
  "sub": "<user-uuid>",
  "tenant": "acme-corp",
  "scope": ["cyberpath.learner"]
}
```

Valid scopes:

| Scope | Description |
|---|---|
| `cyberpath.learner` | Read tracks, start labs, submit completions |
| `cyberpath.instructor` | All learner permissions + manage cohorts, view progress |
| `cyberpath.tenant-admin` | All instructor permissions + manage users within the tenant |
| `cyberpath.admin` | Platform-wide admin; not tenant-scoped |
| `cyberpath.auditor` | Read-only access to completions and audit_events across tenants |

Tokens are validated by the SDK auth middleware before any request
reaches CyberPath's own handlers. The resolved `tenant` claim is used to
set `app.tenant_id` for the duration of the request.

### Onboarding checklist

1. `cyberpath-cli tenant create` — creates the `tenants` row.
2. Request tenant-scoped service tokens from ecosystem auth admin for
   the tenant's instructors.
3. Set the rate-limit profile (see
   [Per-tenant configuration](#per-tenant-configuration)).
4. Assign the CITADEL project ID — each tenant maps to a distinct
   CITADEL project for evidence segregation. Completions emitted for
   this tenant carry `project_id: <citadel_project_id>` in the
   `cyberpath.completion` event.
5. Optionally configure branding overrides and track visibility (v1.1+).
6. Verify the tenant can be resolved by the health probe:
   ```bash
   cyberpath-cli tenant inspect acme-corp
   ```

---

## Per-tenant configuration

Per-tenant configuration is stored as a JSONB column on the `tenants`
row (`config JSONB`) and managed through the admin API or CLI. It is
read at request time (cached in-process, TTL 60s).

### Rate-limit profiles

| Profile | Max learners | API requests/min | Sandbox concurrency |
|---|---|---|---|
| `small` | 100 | 600 | 4 |
| `medium` | 1000 | 3000 | 16 |
| `large` | unlimited | 10000 | 64 |

Set or change the profile:

```bash
cyberpath-cli tenant set-config acme-corp \
    --rate-limit-profile medium
```

Requests that exceed the rate limit receive HTTP 429 with a
`Retry-After` header. Rate limits are per-tenant, not per-user. Use the
`large` profile for tenants with concurrent cohort completions
(end-of-cohort bursts) — see the cohort-of-1000 sizing table in
[operator-handbook.md](operator-handbook.md).

### Branding overrides (v1.1+)

```bash
cyberpath-cli tenant set-config acme-corp \
    --logo-url "https://cdn.acme.example/logo.svg" \
    --primary-color "#2d4a8c" \
    --display-name "Acme Security Academy"
```

Branding is served by the frontend on the `/t/<slug>` tenant-namespaced
URL path. The API is not affected.

### Track catalogue visibility (v1.1+)

By default all tracks in the platform catalogue are visible to all
tenants. To restrict a tenant to a subset:

```bash
cyberpath-cli tenant track-visibility acme-corp \
    --allow phishing-recognition \
    --allow secure-coding-fundamentals \
    --deny-all-others
```

Track visibility is enforced at the API layer; the underlying `tracks`
table is not modified. A tenant set to `--deny-all-others` cannot
enrol learners in tracks outside their allowlist.

### Quotas

| Quota | Config key | Default |
|---|---|---|
| Max users | `quota.max_users` | unlimited |
| Max active cohorts | `quota.max_active_cohorts` | 10 |
| Max sandbox sessions (concurrent) | `quota.max_sandbox_sessions` | profile default |
| Max webhook subscribers | `quota.max_webhooks` | 5 |

```bash
cyberpath-cli tenant set-config acme-corp \
    --quota max_users=500 \
    --quota max_active_cohorts=3
```

Quota violations return HTTP 422 with a machine-readable error code
(`tenant.quota.exceeded`).

---

## Cross-tenant data guarantees

The following guarantees are enforced at both the application layer (JWT
claim validation + `app.tenant_id` session variable) and the database
layer (RLS policies):

1. **No cross-tenant user lookup.** A request authenticated as tenant
   `acme-corp` cannot retrieve, enumerate, or authenticate users
   belonging to `beta-inc` — even if both users share the same email
   address. Email uniqueness is enforced per-tenant:
   `UNIQUE (tenant_id, lower(email))`.

2. **No cross-tenant completion visibility.** Progress and completion
   queries are scoped by `user_id`, which is itself scoped to a tenant
   via `users.tenant_id`.

3. **No cross-tenant cohort or webhook access.** `cohorts` and
   `webhooks` carry `tenant_id` directly; RLS blocks cross-tenant reads.

4. **Shared catalogue is read-only.** Tracks, modules, and lessons are
   shared and readable by all tenants; only platform admins
   (`cyberpath.admin`) can write them. No tenant can modify the shared
   catalogue.

5. **CITADEL evidence segregation.** Each tenant's completions are
   submitted to a distinct CITADEL project. A CITADEL auditor with
   access to tenant A's project cannot see tenant B's ledger entries.

6. **Audit trail is per-platform.** `audit_events` is a platform-wide
   table. Tenant admins have read access scoped to events where the
   `actor` resolves to a user in their tenant. Platform admins can read
   all `audit_events` rows.

---

## Admin vs tenant-admin roles

| Capability | `cyberpath.admin` (platform admin) | `cyberpath.tenant-admin` |
|---|---|---|
| Create / delete tenants | Yes | No |
| View all tenants | Yes | No (own tenant only) |
| Manage users within own tenant | Yes | Yes |
| Manage users across tenants | Yes | No |
| View completions across tenants | Yes | No (own tenant only) |
| Manage cohorts | Yes | Yes (own tenant only) |
| Publish tracks / modules / lessons | Yes | No (content is platform-managed) |
| Configure tenant branding / quotas | Yes | Read-only |
| Rotate CITADEL HMAC secret | Yes | No |
| Rotate certification signing key | Yes | No |
| Read audit_events | All tenants | Own tenant (actor filter) |
| Offboard a tenant | Yes | No |

The `cyberpath.auditor` scope is read-only and crosses tenant boundaries
— it is intended for NIS2 compliance auditors who need to verify
evidence chains across multiple tenants. Auditor tokens must be issued
by the platform admin, not tenant admins.

---

## Tenant offboarding and data export

### Data export

Before offboarding, export all tenant data for handover or archival:

```bash
cyberpath-cli tenant export acme-corp \
    --output /tmp/acme-corp-export/ \
    --format jsonl
```

This exports:

- All `users` rows (PII included; handle securely)
- All `completions` with associated `content_versions` snapshots
- All `certifications` with Ed25519 signatures
- All `cohorts` and `cohort_enrollments`
- All `audit_events` where the actor belongs to this tenant
- A manifest (`manifest.json`) listing all exported files and their
  BLAKE3 checksums

The export does not include `progress` rows (ephemeral in-flight state)
or `lab_sessions` rows older than the configured archival threshold.

Verify the export before proceeding:

```bash
cyberpath-cli tenant verify-export /tmp/acme-corp-export/
```

### Offboarding procedure

Offboarding is irreversible. Follow this sequence:

```bash
# Step 1 — Disable the tenant (blocks new logins and API calls)
cyberpath-cli tenant disable acme-corp
# Sets tenants.config.disabled = true; existing sessions are invalidated
# at next token validation (JWT exp or within 60s for cached sessions).

# Step 2 — Drain in-flight completions
# Wait for cyberpath_citadel_queue_depth to reach 0 for this tenant.
watch -n 10 'psql "$CYBERPATH_DB_URL" -c \
    "SELECT count(*) FROM outbox o
     JOIN completions c ON c.id::text = o.correlation_id::text
     JOIN users u ON c.user_id = u.id
     WHERE u.tenant_id = (SELECT id FROM tenants WHERE slug = '"'"'acme-corp'"'"')
       AND o.submitted_at IS NULL;"'

# Step 3 — Export data (if not already done)
cyberpath-cli tenant export acme-corp --output /tmp/acme-corp-export/

# Step 4 — Soft-delete the tenant
cyberpath-cli tenant offboard acme-corp --confirm
# Sets tenants.deleted_at = now()
# Users and cohorts remain in place with deleted_at set (cascade soft-delete)
# Completions, certifications, and audit_events are retained as audit evidence
```

The soft-delete marks the tenant inactive. FK constraints (ON DELETE
RESTRICT) prevent hard deletion of any row that is referenced by
completion or certification records. Hard deletion of PII
(`email`, `display_name`, `remote_ip`) is part of the v1.1 GDPR erase
procedure described in [data-model.md](data-model.md).

### GDPR erase (v1.1+)

Tenant-level GDPR right-to-erasure is orchestrated as follows:

1. Emit a `cyberpath.erasure` manifest event to CITADEL listing all
   affected `completion_id`s (so the WORM ledger knows PII will be
   severed).
2. Overwrite PII columns on affected rows:
   - `users.email` → `<erased>`
   - `users.display_name` → `<erased>`
   - `audit_events.remote_ip` → `0.0.0.0`
3. Set `tenants.deleted_at`.

The completion *fact* (a record that a completion occurred) remains
indefinitely for audit purposes. The *identity* is severed. This
procedure is described in [data-model.md](data-model.md) and will ship
with a dedicated `cyberpath-cli tenant gdpr-erase` command in v1.1.

---

## See also

- [data-model.md](data-model.md) — `tenants` table, RLS policies, FK cascade rules, GDPR notes
- [operator-handbook.md](operator-handbook.md) — brief onboarding checklist, rate-limit profiles
- [disaster-recovery.md](disaster-recovery.md) — backup scope includes all tenants; restore restores all tenant data
- [migration-guide.md](migration-guide.md) — v1.0.0 RLS migration and v1.1 per-schema migration notes
- [citadel-integration.md](citadel-integration.md) — per-tenant CITADEL project segregation
- [architecture.md](architecture.md) — how JWT claims are resolved to tenant context
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
