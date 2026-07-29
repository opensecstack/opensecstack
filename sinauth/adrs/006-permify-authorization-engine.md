# ADR 006: Permify as the Real Authorization Engine Behind `rbac.Evaluate`

**Status**: Accepted (Phase 1)
**Date**: 2026-07-28
**Deciders**: sinauth core team

**Security fix (2026-07-29)**: a same-day adversarial review found that the
new self-service delegation routes this ADR introduces
(`POST /api/v1/organizations/{id}/members`,
`DELETE /api/v1/organizations/{id}/members/{userId}`,
`AddOwnOrganizationMember`/`RemoveOwnOrganizationMember` in
`internal/api/handlers/organization.go`) reopened the exact
privilege-escalation bug class fixed same-day in
[ADR-005](005-organization-identity.md)'s "Security fix" section. The routes
are gated at the route level (`server.go`) only by `BearerAuth` (any
validly-signed token), by design — see §4 above — relying on
`callerCanManageOrg`'s in-handler check to be the real gate: platform-admin
first, then falling through to `d.Authz.Check(ctx, user, "manage", org)`.
The problem: `authz.New(cfg)` returns `NoopChecker` whenever
`SINAUTH_PERMIFY_URL` is unset — the actual default in this repo's own
`docker-compose.dev.yml` today, since §6 above adds the `permify` service to
compose but nothing makes it the default authorization path until an
operator explicitly deploys and wires it. `NoopChecker.Check` unconditionally
returns `(true, nil)` for any subject/entity. In that default configuration,
any authenticated non-admin user could call the new POST route with
`{"user_id": "<self>", "org_role": "owner"}` for an organization they had no
relationship to (or evict its real owner via the DELETE route) —
`org_role` is fully caller-controlled with no validation, identical in shape
to the ADR-005 bug, just reopened via a new route instead of the old one.

Fixed in `internal/api/handlers/organization.go`'s `callerCanManageOrg`: the
org-owner/admin fallback (`d.Authz.Check`) is now only consulted when
`d.Cfg.PermifyEnabled` is true, i.e. only when `SINAUTH_PERMIFY_URL` is
actually set and `d.Authz` is a real `PermifyChecker`. When Permify is not
deployed, `callerCanManageOrg` denies outright (after the platform-admin
check) rather than asking a `NoopChecker` to make a real authorization
decision it is not equipped to make — matching today's actual admin-only
behavior exactly, with the delegation capability only becoming live once an
operator deploys Permify for real. A regression test,
`TestExploit_SelfServiceOrgRoute_NoopCheckerDoesNotGrantAccess`
(`internal/api/handlers/organization_test.go`), reproduces the exploit
scenario against a real `authz.NoopChecker` with `PermifyEnabled` false and
asserts both the add-self-as-owner and evict-real-owner variants are denied
(403). The existing "platform admin can still manage any org" and "real
Permify-backed owner can manage their own org" tests continue to pass
unchanged (the latter now explicitly sets `PermifyEnabled = true` in its
test helper, matching the "Permify actually deployed" scenario it exercises).

## Context

sinauth has had two RBAC layers that were only half-built. `rbac.Store.Evaluate`
and `rbac.TokenContext` (`internal/rbac/evaluator.go`) existed but had zero
call sites in the real request flow — the `policies` table
(`require_mfa`/`require_email_verified`/`deny_role`) was populated by admin
CRUD but never evaluated at token issuance. The only real authorization
decision sinauth made was `middleware.RequireAdmin`, a flat
`users.is_platform_admin` boolean with no per-resource or per-organization
granularity — exactly why ADR-005 v1.2's "per-org-owner delegation" was
explicitly deferred as unbuilt, and why every `/admin/organizations/*` and
`/admin/rbac/*` route currently requires full platform-admin standing even
for an organization managing its own membership.

Separately, this is also feeding CITADEL's MARSHAL Gate 2 (AuthZ) policy
work: Gate 2 today checks a hardcoded `rbacMap` covering only 5 roles / 10
action types, a real scope gap now that the ecosystem has grown to 11
platforms. That work (a periodically-refreshed local snapshot CITADEL reads,
never a live per-request call to Permify) is **Phase 2**, tracked separately,
and out of scope for this ADR.

## Decision

Adopt [Permify](https://permify.co) — an open-source, Zanzibar-style ReBAC/RBAC
engine — as the real authorization engine backing `rbac.Evaluate`, and as the
new capability behind real per-organization delegation.

### 1. `internal/authz` package

A `Checker` interface (`internal/authz/checker.go`):

```go
type Entity struct {
    Type string // "user", "organization", "group", "client_role"
    ID   string
}

type Relationship struct {
    Entity   Entity
    Relation string
    Subject  Entity
}

type Checker interface {
    Check(ctx context.Context, subject Entity, permission string, entity Entity) (bool, error)
    WriteRelationship(ctx context.Context, rel Relationship) error
    DeleteRelationship(ctx context.Context, rel Relationship) error
}
```

Two implementations, selected the same way `mfa.SMSProvider` picks between
`TwilioProvider` and `NoopSMSProvider` — enablement derived from credential
presence, not a separate boolean an operator can forget to flip:

- **`PermifyChecker`** (`internal/authz/permify.go`) — wraps the real
  Permify Go SDK (`github.com/Permify/permify-go`, gRPC transport via the
  generated `buf.build/gen/go/permifyco/permify/...` client), used when
  `cfg.PermifyEnabled` (`SINAUTH_PERMIFY_URL != ""`).
- **`NoopChecker`** (`internal/authz/noop.go`) — `Check` always returns
  `(true, nil)`; `WriteRelationship`/`DeleteRelationship` are no-ops. This is
  the fail-open default (empty `SINAUTH_PERMIFY_URL`), and it deliberately
  matches two existing precedents rather than inventing a new failure mode:
  `rbac.Store.Evaluate`'s existing "fail open on DB error, don't block
  legitimate logins" comment, and the simple fact that sinauth had *no*
  per-resource authorization gate at all before this ADR — a Checker that
  isn't wired to anything real should reproduce that, not silently start
  denying everything.

`authz.New(cfg *config.Config) Checker` is the single, centralized
construction path both `internal/api/server.go` (the running server) and the
`sinauth permify-sync` backfill CLI call, so they always target the same
Permify instance (or both fall back to Noop together).

### 2. Schema (`sinauth/permify/schema.perm`)

```
entity user {}

entity group {
    relation member @user

    permission view = member
}

entity client_role {
    relation assignee @user

    permission use = assignee
}

entity organization {
    relation owner @user
    relation admin @user
    relation member @user

    permission manage = owner or admin
    permission view = owner or admin or member
}
```

This models exactly the real relation tables that already exist:
`groups`/`group_members`, `client_roles`/`user_client_roles`, and
`organizations`/`organization_members` (`org_role` enum
`owner`/`admin`/`member`) from ADR-005. It does not attempt to cover all 11
SIN platforms' full action vocabularies yet — see Phase 3 below.

`PermifyChecker` writes this schema to Permify lazily, on first use, against
the fixed tenant `t1` (Permify's pre-inserted single-tenant convention — no
`Tenancy.Create` call is required to use it), and caches the returned schema
version for subsequent `Check`/`WriteRelationship` calls. It was validated
by hand against Permify's schema DSL documentation (entity/relation/
permission syntax, `@user` reference syntax, `or` composition) and against
the Go SDK's own generated request/response types — no live Permify server
was available while implementing this, so no `permify validate` CLI run was
performed; the unit tests in `internal/authz/permify_test.go` verify
`PermifyChecker` sends exactly the requests this schema expects, against a
fake gRPC client standing in for a real instance.

### 3. Write-through sync + backfill

`rbac.Store` and `organization.Store` take an optional `authz.Checker` and
call `WriteRelationship`/`DeleteRelationship` immediately after each SQL
mutation that changes a modeled relation (group membership, client-role
assignment, organization membership) succeeds — best-effort, logged not
fatal on Permify write failure. Postgres remains the sole authoritative
store for this data; a failed tuple sync degrades authorization freshness,
never data correctness. A new `sinauth permify-sync` CLI subcommand
backfills tuples for every pre-existing row on first rollout.

### 4. The new capability this unlocks

Real per-organization delegation: `authz.Checker.Check(ctx, user, "manage",
org)` lets an org `owner`/`admin` manage their own organization's membership
without holding platform-admin standing — closing the exact gap ADR-005 v1.2
left open. This is wired as an **additive** check in
`internal/api/handlers/organization.go`'s member-management handlers,
alongside the existing `RequireAdmin` route gate (which stays as the
platform-admin superuser path) — nothing currently reachable only by a
platform admin becomes reachable by fewer checks than before this ADR.

`rbac.Store.Evaluate` is now called from `handlers/token.go`'s authorization
code and refresh grant handlers, before token issuance — this is what
finally makes the `policies` table's `require_mfa`/`require_email_verified`/
`deny_role` rows (creatable via existing admin CRUD, previously inert) take
effect.

### 5. Config

`SINAUTH_PERMIFY_URL` (default `""` → `NoopChecker`) and
`SINAUTH_PERMIFY_TIMEOUT` (default `3s`, bounds every individual
Check/WriteRelationship/DeleteRelationship RPC), following the exact
existing `env`/`envDuration` helper pattern used for every other optional
integration in `internal/config/config.go`. `cfg.PermifyEnabled` is derived
(`cfg.PermifyURL != ""`), mirroring `cfg.SMSEnabled`.

### 6. Deployment

`docker-compose.dev.yml` gains a `permify` service
(`ghcr.io/permify/permify:latest`, `serve --database-engine memory`),
exposing Permify's default ports (3476 REST, 3478 gRPC) with a
`grpc_health_probe`-based healthcheck (bundled in Permify's own official
image) matching the style of the existing `postgres` healthcheck in
`docker-compose.yml`. In-memory storage was chosen for local dev — Permify's
own tuple/schema storage is independent of sinauth's Postgres by design
(these are two separate systems' data, not one shared schema), and in-memory
is the simplest option for a dev loop where the schema is just rewritten and
tuples are backfilled on every restart. Production deployments should use
Permify's own Postgres-backed store per Permify's deployment docs — that
config is an operational decision for the deploying environment, not
something this dev compose file needs to prescribe.

## Non-Goals (this ADR)

- **CITADEL Gate 2 policy sync** — reading a Permify-derived role→action
  snapshot into CITADEL's MARSHAL AuthZ gate. This is Phase 2, gated behind
  a new flag defaulting `false` (mirroring `EnforceIdentity`/
  `EnforceSignatures`, ADR-006 in the CITADEL tree) so no platform's current
  behavior changes when it ships. Tracked separately.
- **Flipping any enforcement default, or extending the schema to the full
  11-platform action vocabulary, or an org-owner-delegation admin UI.**
  These are Phase 3 — explicitly deferred, not built speculatively, per this
  ecosystem's established pattern for phasing large ADR-driven changes.
- **Multi-tenant Permify.** sinauth is single-tenant today; the fixed `t1`
  tenant ID is a deliberate simplification, not a limitation baked
  permanently into the `Checker` interface (which does not expose a tenant
  parameter to callers).

## Trade-offs

- **A new outbound service dependency.** sinauth had zero outbound service
  dependencies before this ADR (`go.mod` had no grpc/connectrpc). Accepted:
  the `NoopChecker` fallback means sinauth never hard-fails if Permify is
  unreachable — this is additive capability, not a new single point of
  failure for the OIDC flows that already work.
- **Best-effort sync means Permify can be briefly stale relative to
  Postgres** after a write, until the next successful sync or a
  `permify-sync` backfill run. Accepted per the same fail-open precedent
  `rbac.Evaluate` already established: Postgres is authoritative for data;
  Permify staleness affects authorization freshness only, and closing that
  gap immediately (e.g. by making sync synchronous-and-blocking with the SQL
  transaction) would mean an unrelated infrastructure outage could break
  login/admin flows that worked yesterday.
- **The `.perm` schema and the `permifySchema` Go constant are two copies of
  the same text**, because Go's `//go:embed` cannot embed a file outside its
  own package's directory tree, and `sinauth/permify/schema.perm` lives
  outside `internal/authz/`. Accepted for now; a `go:generate` step to keep
  them mechanically in sync is a reasonable low-risk follow-up, not required
  for Phase 1.

## Consequences

- `internal/authz` is a new package: `Checker`, `Entity`, `Relationship`,
  `PermifyChecker`, `NoopChecker`, `New(cfg) Checker`.
- New config: `SINAUTH_PERMIFY_URL`, `SINAUTH_PERMIFY_TIMEOUT`,
  `cfg.PermifyEnabled`.
- New `go.mod` dependencies: `github.com/Permify/permify-go`,
  `buf.build/gen/go/permifyco/permify/...` (generated protobuf/gRPC client),
  `google.golang.org/grpc`.
- New file: `sinauth/permify/schema.perm`.
- New docker-compose service: `permify`.
- `rbac.Store.Evaluate` is finally called at token issuance, making
  previously-inert `policies` rows take effect.
- Organization owners/admins can manage their own organization's membership
  without platform-admin standing, for the first time since ADR-005.
- Phasing:
  - **Phase 1 (this ADR)**: `internal/authz`, schema, write-through sync +
    backfill CLI, token-issuance wiring, org-delegation check, config,
    docker-compose.
  - **Phase 2 (deferred, separate ADR in the CITADEL tree)**: CITADEL Gate 2
    reads a periodically-refreshed local snapshot derived from this same
    Permify instance/schema — never a live per-request call — behind a new
    flag defaulting `false`.
  - **Phase 3 (deferred)**: flip enforcement defaults after burn-in, extend
    the schema to the full 11-platform action vocabulary, build an
    org-owner-delegation admin UI on top of the fine-grained checks this ADR
    makes possible.
