# Changelog

All notable changes to sinauth will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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
