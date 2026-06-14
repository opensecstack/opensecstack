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
