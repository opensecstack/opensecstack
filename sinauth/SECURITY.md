# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | Yes |

## Reporting a Vulnerability

Email: security@sin.to
Response time: 48 hours
Disclosure: coordinated after patch

## Security Model

- Private keys never leave the server
- All tokens signed RS256
- PKCE required for all clients
- Bcrypt cost 12 for passwords
- Audit log for all auth events

## Platform Admin Model

Every `/admin/*` route (organizations, RBAC groups, RBAC roles/policies,
OAuth client management, user management, audit log, sessions, federation
providers) requires **platform-admin standing**, not just a validly-signed
bearer token. This is enforced by `middleware.RequireAdmin`
(`internal/api/middleware/auth.go`), which checks the caller's
`users.is_platform_admin` flag (`migrations/019_platform_admin.sql`) and
returns `403 Forbidden` for any authenticated user who isn't a platform
admin.

This closes a vulnerability found and fixed on 2026-07-27: those routes
previously used `BearerAuth` alone (valid signature + not expired, no
authorization check), so any authenticated user could create/delete
organizations and RBAC groups, and grant themselves membership — including
`org_role: "owner"` — in an organization or group they had no legitimate
connection to. See `adrs/005-organization-identity.md` for the full writeup.

The fix shipped in two passes on the same day: the initial patch gated only
`/admin/organizations/*` and `/admin/rbac/groups/*` (the routes exploited in
the reported issue); a same-day follow-up applied the identical
`RequireAdmin` pattern to the remaining `/admin/*` route groups that shared
the same `BearerAuth`-only gap (OAuth client management, user management,
audit log, sessions, federation providers, RBAC client-roles/policies).
`/admin/*` is now uniformly gated — no route group in that namespace relies
on `BearerAuth` alone.

Self-service MFA endpoints (`/api/v1/mfa/webauthn/*`, `/api/v1/mfa/sms/*`)
are intentionally exempt from `RequireAdmin`: they act only on the calling
user's own credentials (resolved from the token's `sub` claim), not on
arbitrary users, so plain `BearerAuth` is the correct control there.

The model is deliberately coarse-grained: a platform admin manages *all*
organizations and groups. Per-org-owner delegation now exists (see
below) but is inert unless an operator explicitly deploys Permify.

### Org-delegation security posture

`internal/authz`'s `authz.Checker` (`PermifyChecker` / `NoopChecker`,
selected by whether `SINAUTH_PERMIFY_URL` is set) backs a new,
additive capability: an org `owner`/`admin` can manage their own
organization's membership (`POST`/`DELETE
/api/v1/organizations/{id}/members`) without platform-admin standing.
This is **inert by default**. `callerCanManageOrg` only falls through
to `d.Authz.Check(ctx, user, "manage", org)` when
`d.Cfg.PermifyEnabled` is true — i.e. only once an operator has
actually deployed Permify and set `SINAUTH_PERMIFY_URL`. With no
Permify deployment (today's default, including this repo's own
`docker-compose.dev.yml`), the route denies any non-platform-admin
caller outright, matching the existing admin-only behavior exactly.

This closes a same-day privilege-escalation bug found and fixed on
2026-07-29: before the fix, `callerCanManageOrg` consulted
`d.Authz.Check` regardless of `PermifyEnabled`, and an unconfigured
`NoopChecker.Check` unconditionally returns `(true, nil)` — so any
authenticated non-admin user could add themselves as `owner` of, or
evict the real owner from, an organization they had no relationship
to, identical in shape to the 2026-07-27 bug documented above. See the
"Security fix (2026-07-29)" section of
`adrs/006-permify-authorization-engine.md` for the full writeup and
the regression test
(`TestExploit_SelfServiceOrgRoute_NoopCheckerDoesNotGrantAccess`).

### Bootstrapping the first platform admin

A fresh sinauth deployment has zero platform admins (`is_platform_admin`
defaults to `false` for every user). Register a normal user account first
(e.g. via `POST /api/v1/auth/register`), then promote it using **one** of:

**Option A — CLI (recommended, works against a running or stopped server):**

```bash
sinauth promote-admin admin@example.com
# to revoke:
sinauth promote-admin admin@example.com --revoke
```

**Option B — environment variable, applied on every `sinauth serve` startup:**

```bash
export SINAUTH_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
sinauth serve
```

This is idempotent and safe to leave set permanently in the deploy
environment; it only takes effect if a user with that email already exists,
and simply re-affirms admin status on every restart otherwise it's a no-op.

**Option C — direct SQL (matches the existing OAuth-client bootstrap pattern
in `docs/admin-guide.md`):**

```sql
UPDATE users SET is_platform_admin = true WHERE email = 'admin@example.com';
```

Once at least one platform admin exists, subsequent admins can be granted
the same way, or (once implemented) via an `/admin/*` endpoint restricted to
existing platform admins.
