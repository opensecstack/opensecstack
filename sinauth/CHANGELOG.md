# Changelog

All notable changes to sinauth will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **`internal/authz` package + Permify integration** — a `Checker`
  interface backed by `PermifyChecker` (real authorization via
  [Permify](https://permify.co), a Zanzibar-style ReBAC/RBAC engine)
  or `NoopChecker` (fail-open no-op default when unconfigured), the
  latter selected whenever `SINAUTH_PERMIFY_URL` is unset. This is now
  the real engine behind `rbac.Store.Evaluate` and behind new
  self-service `/api/v1/organizations/{id}/members` routes allowing an
  org owner/admin to manage their own organization's membership
  without platform-admin standing. New config: `SINAUTH_PERMIFY_URL`,
  `SINAUTH_PERMIFY_TIMEOUT`. New `sinauth permify-sync` CLI subcommand
  to backfill existing rows into Permify. New `docker-compose.dev.yml`
  `permify` service for local dev. See
  `adrs/006-permify-authorization-engine.md`.
- OIDC Authorization Server core (authorization_code + PKCE)
- RS256 token signing with JWKS endpoint
- OpenID Connect discovery document
- OAuth2 client (platform) management
- Refresh token support
- SSO session management
- Bcrypt password hashing (cost 12)
- Rate limiting on auth endpoints (5 req/min per IP)
- PostgreSQL-backed token store
- Docker + Helm deployment
- Go SDK client in opensecstack/sdk

### Security
- Fixed a same-day privilege-escalation bug (2026-07-29) in the new
  self-service org-delegation routes: `callerCanManageOrg` consulted
  `d.Authz.Check` regardless of whether Permify was actually deployed,
  so an unconfigured `NoopChecker` (which unconditionally returns
  `(true, nil)`) let any authenticated non-admin user add themselves
  as `owner` of, or evict the real owner from, an organization they
  had no relationship to. Fixed by gating the `d.Authz.Check` fallback
  on `d.Cfg.PermifyEnabled`: with no Permify deployment, the route now
  denies non-admins outright. See `SECURITY.md` and
  `adrs/006-permify-authorization-engine.md`.
- Fixed missing authorization on `/admin/organizations/*` and
  `/admin/rbac/groups/*`: these routes previously accepted any validly-signed
  bearer token (`BearerAuth`) with no admin check, letting any authenticated
  user create/delete organizations and RBAC groups and grant themselves
  membership — including `org_role: "owner"` — in organizations they had no
  connection to. Added `users.is_platform_admin` and `middleware.RequireAdmin`
  to gate these routes. See `SECURITY.md` and `adrs/005-organization-identity.md`.
