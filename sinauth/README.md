# sinauth

SIN Identity Provider — OIDC Authorization Server for the [OpenSecStack](https://opensecstack.org) (SIN) ecosystem.

sinauth is what [Porta](https://porta.gjirafa.tech) is for Gjirafa and [Auth0](https://auth0.com) is globally — a dedicated OAuth 2.0 / OpenID Connect authorization server that gives every SIN platform a single, shared identity layer.

## What sinauth does

- One account → access to all 10 SIN platforms
- Issues RS256-signed ID tokens and access tokens
- Standards: OAuth 2.0 + OpenID Connect Core 1.0
- Social login: Google, GitHub
- MFA: TOTP (authenticator apps)
- Admin dashboard for managing OAuth clients (platforms)

## Quick start

```bash
# 1. Generate signing key
make keys-generate

# 2. Start with Docker Compose
docker compose -f docker-compose.dev.yml up

# 3. Run migrations
make migrate DB_URL=postgres://sinauth:sinauth@localhost:5433/sinauth

# 4. sinauth is live at http://localhost:8100
# OIDC discovery: http://localhost:8100/.well-known/openid-configuration
```

## Authorization (`internal/authz`)

sinauth's real authorization decisions — beyond the flat
`users.is_platform_admin` check — are backed by an `authz.Checker`
interface (`internal/authz/checker.go`), with two implementations:

- **`PermifyChecker`** — wraps [Permify](https://permify.co), an
  open-source Zanzibar-style ReBAC/RBAC engine, used whenever
  `SINAUTH_PERMIFY_URL` is set. This is the real authorization engine
  behind `rbac.Store.Evaluate` (finally making the `policies` table's
  `require_mfa`/`require_email_verified`/`deny_role` rows take effect
  at token issuance) and behind the self-service org-delegation
  routes (`POST`/`DELETE /api/v1/organizations/{id}/members`).
- **`NoopChecker`** — the default when `SINAUTH_PERMIFY_URL` is unset
  (empty, out of the box). `Check` always returns `(true, nil)`, but
  because `callerCanManageOrg` only ever *consults* `d.Authz.Check` when
  `d.Cfg.PermifyEnabled` is true, an unconfigured `NoopChecker` never
  actually gets asked to make a real authorization decision — org
  delegation stays **platform-admin-only** until Permify is deployed.
  This is inert-by-design, not fail-open: see the "Security fix
  (2026-07-29)" section of
  [`adrs/006-permify-authorization-engine.md`](adrs/006-permify-authorization-engine.md)
  for the same-day bug this design closes.

Config: `SINAUTH_PERMIFY_URL` (default `""` → `NoopChecker`) and
`SINAUTH_PERMIFY_TIMEOUT` (default `3s`, bounds every
Check/WriteRelationship/DeleteRelationship RPC).

Backfill existing rows into Permify with the CLI, after deploying it:

```bash
sinauth permify-sync
```

For local dev, `docker-compose.dev.yml` includes a `permify` service
(`ghcr.io/permify/permify:latest`, in-memory storage) so
`SINAUTH_PERMIFY_URL` can point at it without standing up a separate
instance. See [`adrs/006-permify-authorization-engine.md`](adrs/006-permify-authorization-engine.md)
for the full design.

## Integrating a platform

See [docs/integration/](docs/integration/) for per-platform guides.

Generic OIDC integration (any platform):
```
Issuer:                https://auth.sin.to
Authorization:         https://auth.sin.to/oauth/authorize
Token:                 https://auth.sin.to/oauth/token
UserInfo:              https://auth.sin.to/oauth/userinfo
JWKS:                  https://auth.sin.to/.well-known/jwks.json
Scopes:                openid profile email
Grant type:            authorization_code + PKCE (S256)
```

## Documentation

- [Quick Start](docs/quick-start.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Key Management](docs/key-management.md)
- [API Reference](docs/api-reference.md)
- [Security](docs/security.md)
- [Deployment](docs/deployment.md)

## Part of SIN

| Platform | Purpose |
|---|---|
| **sinauth** | Identity Provider (this repo) |
| APIGuard | API security testing |
| IRFlow | Incident response |
| NIS2Compass | NIS2 compliance |
| ThreatFlow | Threat intelligence |
| Community | Developer knowledge hub |
| ... | 6 more platforms |

## License

Apache 2.0 — see [LICENSE](LICENSE)
