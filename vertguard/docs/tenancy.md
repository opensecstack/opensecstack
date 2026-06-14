# VertGuard Multi-Tenant Operations Guide

VertGuard ships in two deployment shapes:

- **Single-tenant** — one customer, one Postgres, one JWT issuer. The
  default for a sectoral operator running their own instance.
- **Multi-tenant** — a national CSIRT (e.g. ASNI/AL-CERT) running one
  VertGuard for several sectoral operators. Each operator is a *tenant*
  with isolated views over prompts, IOCs, audit trail, and quotas.

This guide covers the multi-tenant operating model. For the
single-tenant baseline see
[operator-handbook.md](operator-handbook.md) and
[operator-runbook.md](operator-runbook.md).

---

## Tenancy model

VertGuard v1.0.0 implements **subject-scoped tenancy at the handler
layer**. There is no row-level tenant column in Postgres yet — the
isolation contract is:

- **Tenant ID = JWT `sub` claim.** Recommended naming convention:
  `tenant:<short-name>` (e.g. `tenant:energy-op`,
  `tenant:health-op`). Service accounts inside a tenant should be
  `svc:<tenant>:<purpose>` (e.g. `svc:energy-op:siem-pull`).
- **JWT claims actually verified** (see `internal/auth/jwt.go`):
  `sub`, `role`, `iss`, `exp`, `iat`, `jti`. There is no dedicated
  `tenant` claim — the subject *is* the tenant identifier. Roles
  (`internal/auth/roles.go`) are orthogonal: `admin`, write, read.
- **No Postgres-level row tenancy in v1.0.0.** Tables
  (`audit_events`, `phishing_scans`, `identity_scans`,
  `rate_limit_overrides`, `webhook_subscribers`,
  `token_denylist`) carry an `actor`/`subject` column that handlers
  filter on. A tenant administrator querying the audit API sees only
  rows where `actor` matches their subject prefix; a CSIRT-global
  admin sees everything.
- **Row-level tenancy migration is planned for v1.1+** (see
  Limitations below). Until then, a buggy handler that forgets the
  subject filter is the failure mode to guard against — covered by the
  cross-tenant integration tests in `tests/`.

### CITADEL chain partitioning

CITADEL events carry an explicit `tenant` field
(`internal/citadel/client.go`). VertGuard sets this to the JWT
`sub` of the originating request. Two tenants operating against the
same CITADEL anchor get logically separated event streams keyed by
`(tenant, event_subject)`. See
[citadel-integration.md](citadel-integration.md) for the schema.

---

## Provisioning a new tenant

Multi-tenant deploys assume a CSIRT-operated **JWT issuer service**
(out of scope for VertGuard itself — usually Keycloak, Authentik, or a
small in-house signer) that mints HS256 tokens with the shared
secret(s) configured in `VERTGUARD_JWT_SECRET` /
`VERTGUARD_JWT_SECRET_NEXT` / `VERTGUARD_JWT_SECRET_PREVIOUS`.

To onboard a tenant:

1. **Reserve the tenant short-name.** Lowercase, hyphenated,
   `[a-z0-9-]{3,32}`. Record it in your tenant registry (a CSV in the
   ops repo is fine). The chosen name becomes the `tenant:<name>`
   prefix used in every JWT, every CITADEL event, and every Prometheus
   label.

2. **Issue the tenant's JWT signing config.** In a multi-tenant
   deployment, all tenants share the same VertGuard verifier secret
   (rotation-capable, see `NewVerifierMulti`). The issuer service is
   responsible for never minting a `sub` outside the tenant's
   namespace.

3. **Create rate-limit overrides** for the tenant's expected load:

   ```bash
   curl -sS -X POST https://vertguard.example/api/v1/admin/ratelimit/overrides \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -d '{
       "kind":"sub",
       "value":"tenant:energy-op",
       "rps": 50,
       "burst": 200,
       "reason":"onboarding tier-2 SLA",
       "created_by":"alice@csirt"
     }'
   ```

   The `Override` shape is in `internal/ratelimit/overrides.go`. Set
   `expires_at` for trial tenants; omit for production.

4. **Register the tenant in CITADEL** by ensuring downstream consumers
   filter on `tenant=<short-name>`. VertGuard tags every event
   automatically; no extra config inside VertGuard.

5. **Audit log cardinality budget.** Every state-changing API call
   produces one row in `audit_events`. Budget ~5 rows/sec/tenant
   sustained. Above that, audit retention compaction
   (see operator-runbook) must run more frequently than the default
   weekly cycle.

---

## Onboarding checklist

Tick each item before handing credentials to the tenant:

- [ ] Tenant short-name reserved in the registry.
- [ ] JWT issuer configured to mint `sub=tenant:<short-name>` and the
      VertGuard verifier secret rotation slots
      (`VERTGUARD_JWT_SECRET`, `..._NEXT`, `..._PREVIOUS`) populated.
- [ ] Rate-limit override applied (`POST /api/v1/admin/ratelimit/overrides`).
- [ ] SLA tier recorded (tier-1 = 100 rps, tier-2 = 50 rps, tier-3 =
      10 rps — adjust to your CSIRT's pricing).
- [ ] Dashboard access granted: tenant gets a read-role JWT scoped to
      their `sub` for the React dashboard under `web/`.
- [ ] NIS2 sectoral mapping recorded (Annex I/II sector + entity
      type — essential vs important). See
      [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md).
- [ ] Tenant added to the CSIRT runbook contact list with on-call
      pager + secure email.
- [ ] Smoke test from tenant side: scan one prompt, fetch one IOC,
      confirm audit event lands.

---

## Cross-tenant guardrails

The contract between tenants:

- **Tenants MUST NOT see each other's prompt scans, phishing scans,
  identity scans, or webhook deliveries.** The handler layer filters
  every list/read endpoint by `actor = claims.Sub` (or a prefix match
  for tenant-scoped service accounts). The audit middleware
  (`internal/audit/middleware.go`) records `actor` from
  `auth.ClaimsFromContext`, so the trail itself is filterable.
- **Tenants CAN see global threat-feed IOCs.** ThreatFlow IOCs
  ingested via `internal/threatfeed/` are explicitly *global*: the
  whole point of a national CSIRT is sharing IOCs across operators.
  Tenants get the union, not their slice. See
  [threatflow-integration.md](threatflow-integration.md).
- **Admin role bypasses tenant filtering** — reserve the `admin` role
  for CSIRT staff only. Never mint admin JWTs with
  `sub=tenant:<short-name>`; admin JWTs use `sub=csirt:<operator>`.
- **Per-tenant Prometheus labels** are emitted on the request,
  rate-limit, and audit metrics so cost attribution is mechanical.
  Cardinality cap: bucket by tenant short-name, not raw `sub` —
  service-account subjects share their tenant's bucket.

---

## Quotas + billing

- **Token bucket per tenant.** `internal/ratelimit/limiter.go` keys
  buckets by `sub:<value>`; the override store
  (`internal/ratelimit/overrides.go`) lets the CSIRT raise/lower the
  ceiling per tenant without restart. Expired overrides are dropped on
  the next snapshot refresh.
- **Threshold alerts.** Alert when a tenant sustains >80 % of their
  configured RPS for 5 minutes. A Prometheus rule example lives in
  `deploy/` next to the alerting bundle — copy the per-subject
  rate-limit metric and group by the tenant label.
- **No built-in billing in v1.0.0.** Export the per-tenant request
  counter from Prometheus into your usage system of choice
  (Stripe metered billing, an internal cost-of-service report, etc.).
  Sample export query:

  ```promql
  sum by (tenant) (
    increase(vertguard_http_requests_total[30d])
  )
  ```

---

## Threat model

What a tenant **CAN** do:

- Scan their own prompts via `POST /api/v1/prompt/scan`.
- Submit and read their own phishing / identity / media scans.
- Read the **global** ThreatFlow IOC feed and the global ATLAS
  technique mapping.
- Read their own audit events and webhook deliveries.
- Rotate their own service-account JTIs via the denylist
  (`internal/auth/denylist`).

What a tenant **CANNOT** do:

- Read another tenant's prompt scans, phishing scans, identity scans,
  audit events, or webhook payloads.
- Read another tenant's CITADEL events (the CITADEL anchor enforces
  the `tenant` field on read; VertGuard does not expose a
  cross-tenant CITADEL read API to non-admin roles).
- Modify rate-limit overrides — only admin role.
- Mint or revoke JWTs for other tenants — that's an issuer-service
  concern, not VertGuard's.
- Subscribe webhook receivers to another tenant's namespace.

The CSIRT (admin role) can see and do everything — that's the point of
running multi-tenant.

---

## Limitations + v1.1 roadmap

Known limitations in v1.0.0:

- **No row-level tenant column.** Isolation is handler-enforced. A
  rogue handler is the failure mode; mitigated by integration tests
  but not by the database. Planned for v1.1+.
- **No soft-delete or GDPR right-to-erase per tenant.** Removing a
  tenant today means a manual `DELETE` script against
  `audit_events`, `phishing_scans`, `identity_scans` filtered by
  `actor` — and CITADEL events stay anchored forever (the chain is
  append-only by design). Planned for v1.1+: a `tenant_lifecycle`
  table and a `make tenant-erase TENANT=...` target.
- **One model head per deployment.** Every tenant shares the same
  DistilBERT prompt-injection classifier. High-volume tenants who
  want a tuned head must run their own VertGuard instance. Per-tenant
  model heads are planned for v1.1+ — see
  [ml-architecture.md](ml-architecture.md).
- **Rate-limit override store is in-memory + DB-backed snapshot.**
  Updates propagate within the snapshot refresh interval; not
  instant. Acceptable for human-driven onboarding, not for automated
  per-request quota changes.

---

## See also

- [operator-handbook.md](operator-handbook.md) — single-tenant
  operating baseline.
- [operator-runbook.md](operator-runbook.md) — incident response,
  backup/restore, audit retention.
- [citadel-integration.md](citadel-integration.md) — CITADEL event
  schema with the `tenant` field.
- [threatflow-integration.md](threatflow-integration.md) — why the
  IOC feed is global, not per-tenant.
- [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md) — sectoral
  classification reference.
- [security-model.md](security-model.md) — JWT, denylist, rotation.
- [migration-guide.md](migration-guide.md) — version upgrades.
