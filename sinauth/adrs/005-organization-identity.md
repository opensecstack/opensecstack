# ADR 005: Organizations as a First-Class Identity Subject

**Status**: Partially Accepted — v1.1 implemented (see below); v1.2/v2.0 still Proposed
**Date**: 2026-07-26
**Deciders**: sinauth core team

**Implementation note (2026-07-27)**: v1.1 (organizations + organization_members,
optional `org_id`/`org_role`/`org_type` token claims, org-picker for multi-org
users) is implemented — `migrations/018_organizations.sql`, `internal/organization`,
`internal/api/handlers/organization.go`, the `AuthorizePOST`/`handleAuthCodeGrant`
org-context wiring, and `web/src/pages/OrgPicker.tsx`. v1.2 (`client_credentials`
for organization M2M clients, CITADEL-gated activation) and v2.0 (org-scoped
federation) remain unimplemented, as originally phased below.

**Security fix (2026-07-27)**: a same-day audit found that `/admin/organizations/*`
(and, same bug class, `/admin/rbac/groups/*`) were protected only by
`BearerAuth` — which proves a token is validly-signed and unexpired but
performs **no authorization check** — combined with `AddOrganizationMember`
accepting the caller-supplied `org_role` unconditionally. Any authenticated
user could therefore call `POST /admin/organizations/{id}/members` with
`{"user_id": "<self>", "org_role": "owner"}` for an organization they had
never been a member of, then re-authorize with `organization_id=<that org>`
to mint a token carrying `org_role:"owner"` for it. sinauth had no concept
of a platform-level admin at all prior to this fix (`client_roles`/
`user_client_roles` from `migrations/012_rbac.sql` model per-client roles,
not a platform-wide admin standing, and no seed/bootstrap ever populated
them for sinauth itself).

Fixed by adding a minimal `users.is_platform_admin` flag
(`migrations/019_platform_admin.sql`) and a new `middleware.RequireAdmin`
(`internal/api/middleware/auth.go`) that composes `BearerAuth` with a check
against that flag, returning 403 for authenticated-but-non-admin callers.
`internal/api/server.go` initially routed only `/admin/organizations/*` and
`/admin/rbac/groups/*` (the routes exploited in the reported issue) through
`RequireAdmin` instead of plain `BearerAuth`; a same-day fast-follow applied
the identical pattern to every other `/admin/*` route group that shared the
same `BearerAuth`-only gap — OAuth client management (`/api/v1/admin/clients`),
user management (`/api/v1/admin/users`), audit log (`/api/v1/admin/audit`),
sessions (`/api/v1/admin/sessions`), federation providers
(`/admin/federation/providers`), and RBAC client-roles/policies
(`/admin/rbac/clients/*/roles`, `/admin/rbac/roles/*`, `/admin/rbac/users/*/roles`,
`/admin/rbac/policies`). Every `/admin/*` route now requires platform-admin
standing; none remain on plain `BearerAuth`. Self-service MFA endpoints
(`/api/v1/mfa/webauthn/*`, `/api/v1/mfa/sms/*`) were deliberately left on
plain `BearerAuth` — they act only on the calling user's own credentials,
not on arbitrary users, so there is no privilege-escalation gap to close
there. The current model is coarse-grained by design (platform-admin
manages all organizations/groups; no per-org-owner delegation yet) — see
SECURITY.md for the operator bootstrap procedure for the first platform
admin.

## Context

sinauth v1 recognizes exactly one kind of identity subject: an individual
`user` (email + password or social login), authenticated via
Authorization Code + PKCE. Every OAuth client in `oauth_clients` is a SIN
*platform* (apiguard, community, ...), never an external party.

The ecosystem needs sinauth to also authenticate on behalf of
**organizations** — government institutions, private companies,
e-commerce businesses — while continuing to serve individual users.
Both subject types must coexist: the same platform (e.g. NIS2 Compass)
is used both by an individual security researcher and by a compliance
officer acting on behalf of a specific institution, and a single human
user may act on behalf of more than one organization (e.g. an external
consultant).

This is materially different from sinauth's current job. It is also
*not* a request to reimplement X-Road: sinauth is not becoming an
inter-organizational data-exchange bus with security servers and
per-message signing. The scope here is narrower — organizations need to
be a recognized identity subject with membership, roles, and
machine-to-machine credentials, the same way Auth0 Organizations or
WorkOS model B2B tenants.

## Decision

Add `organization` as a second identity subject type, alongside
`user`, without breaking the individual-user flow that already works.

### 1. Organization as an entity

New table `organizations`:

```sql
CREATE TABLE organizations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name         TEXT NOT NULL,
    slug               TEXT UNIQUE NOT NULL,
    org_type           TEXT NOT NULL CHECK (org_type IN
                         ('government','private','ecommerce','ngo')),
    registration_number TEXT,        -- NIPT / business registry ID
    verified_at        TIMESTAMPTZ,  -- NULL until KYB step passes
    verified_by        TEXT,         -- CITADEL Kerkese reference
    status             TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','active','suspended')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 2. Membership (many-to-many)

```sql
CREATE TABLE organization_members (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_role        TEXT NOT NULL DEFAULT 'member'
                      CHECK (org_role IN ('owner','admin','member')),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);
```

A user with zero organization memberships behaves exactly as today
(pure individual). A user with one or more memberships can act as
themselves *or* on behalf of one of their organizations — never both
at once in a single token.

### 3. Organization context in tokens (optional claim)

`/oauth/authorize` gains an optional `organization_id` parameter. When
present and the user is a member, the issued ID token and access token
carry:

```json
{
  "sub": "user-uuid",
  "org_id": "org-uuid",
  "org_role": "admin",
  "org_type": "government"
}
```

When absent, tokens are issued exactly as in v1 (no `org_*` claims).
Platforms that don't care about organizations ignore the claims
entirely — this is additive, not a breaking change to the token shape.

If a user belongs to more than one organization and omits
`organization_id`, the authorize endpoint returns an
organization-picker step (analogous to the existing consent screen)
instead of guessing.

### 4. Organizations as machine-to-machine subjects

`oauth_clients` gains an `owner_organization_id` (nullable) and
`client_kind` column (`platform` | `organization`):

```sql
ALTER TABLE oauth_clients
  ADD COLUMN owner_organization_id UUID REFERENCES organizations(id),
  ADD COLUMN client_kind TEXT NOT NULL DEFAULT 'platform'
    CHECK (client_kind IN ('platform','organization'));
```

Organization-owned clients use `client_credentials` (new grant type,
not currently in `oauth_clients.grant_types`) so an organization's own
backend system can call SIN platform APIs without a human in the loop.
Client authentication for `client_kind = 'organization'` MUST use
`private_key_jwt` or mTLS (RFC 8705) — shared `client_secret` is not
acceptable for unattended, higher-trust org credentials. This is the
one piece deliberately modeled after X-Road's PKI-based member trust,
expressed through standard OIDC mechanisms rather than a bespoke
protocol.

Access tokens issued via `client_credentials` carry `org_id` and
`org_type` but no `sub` (no human is attached).

### 5. Org-scoped RBAC

Extend the existing per-platform RBAC (`client_roles`,
`user_client_roles`) with an organization dimension:

```sql
CREATE TABLE organization_client_roles (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    role_name       TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id, client_id, role_name)
);
```

`rbac.TokenContext` (`internal/rbac/evaluator.go`) gains `OrgID` and
`OrgRole` fields so policies can be scoped to organization context
(e.g. "require_mfa" only when acting on behalf of a `government` org).

### 6. Verification (KYB) is a governed action, not admin CRUD

Creating an `organizations` row starts in `status = 'pending'`. Moving
it to `active` (i.e. granting the organization and its members real
access) is a **CITADEL-governed action** — submitted to MARSHAL like
any other privileged action in the ecosystem — not a bare admin
endpoint. Verification evidence (business registry lookup for
`private`/`ecommerce`, official domain/registry check for
`government`) is attached to the Kerkese and the resulting verdict is
WORM-logged. This mirrors X-Road's Central-Server trust-establishment
step, but reuses infrastructure the ecosystem already has instead of
building a parallel trust registry.

## Non-Goals

- No per-message signing or Security-Server-style mutual TLS bus
  between organizations and SIN platforms. Organizations call platform
  APIs directly over the existing OIDC/HTTPS model.
- No org-scoped federation (org brings its own IdP/LDAP) in this ADR —
  `internal/federation` already exists for individual-account
  federation; extending it to be organization-scoped is a follow-up
  ADR once basic org identity ships.
- No change to how the 11 SIN platforms themselves authenticate to
  sinauth (`client_kind = 'platform'` keeps today's behavior
  unchanged).
- No data-residency or per-organization region pinning.

## Trade-offs

- **Token claim ambiguity for existing platforms**: platforms that
  start caring about `org_id` must be updated to enforce
  organization-based data isolation themselves (this ADR only makes
  the claim available — it does not retrofit tenant isolation into
  each platform's own database). That is a per-platform follow-up
  tracked via the SDK contract version bump, not part of sinauth.
- **Org picker adds a step** for multi-org users. Accepted — silently
  guessing which organization a token should represent is a security
  bug waiting to happen.
- **KYB routed through CITADEL adds latency to org onboarding**
  (no longer instant, admin-approved). Accepted — an unverified
  organization getting a working `client_credentials` credential is a
  worse outcome than a slower onboarding flow.

## Consequences

- sinauth issues tokens for two subject types: individual (unchanged
  from v1) and individual-acting-for-organization / organization-M2M
  (new).
- SDK contract bump: `org_id` / `org_role` / `org_type` become
  optional standard claims across all typed clients (Go, Python,
  TypeScript, Rust).
- New migrations: `organizations`, `organization_members`,
  `organization_client_roles`, plus `owner_organization_id` /
  `client_kind` on `oauth_clients`.
- New grant type `client_credentials`, restricted to
  `client_kind = 'organization'`, authenticated via `private_key_jwt`
  or mTLS only.
- Organization activation becomes a CITADEL MARSHAL-evaluated,
  WORM-logged action.
- Phasing (suggested, not binding on this ADR):
  - **v1.1**: `organizations` + `organization_members` + optional
    `org_id`/`org_role` claims + org picker UI. Individual-user flow
    untouched.
  - **v1.2**: `client_credentials` for organization clients +
    `private_key_jwt`/mTLS client auth + CITADEL-gated activation.
  - **v2.0**: organization-scoped federation (bring-your-own-IdP per
    organization), building on the existing `internal/federation`
    package.
