# Configuration

sinauth is configured entirely through environment variables. Copy `.env.example` to `.env` and set the values for your environment.

In production, inject variables through your deployment system (Docker secrets, Kubernetes `Secret` objects, Vault, etc.) rather than committing a `.env` file.

## Server

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_HTTP_ADDR` | `:8100` | No | TCP address the HTTP server listens on. Use `:8100` for all interfaces or `127.0.0.1:8100` to bind to localhost only. |
| `SINAUTH_DEV_MODE` | `false` | No | When `true`, skips required-field validation so the server starts without a DB URL or signing key. Never enable in production. Accepts `true`, `1`, `yes`. |

## Database

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_DB_URL` | — | Yes (prod) | PostgreSQL connection string. Example: `postgres://sinauth:secret@db:5432/sinauth?sslmode=require` |
| `SINAUTH_DB_MAX_CONNS` | `20` | No | Maximum number of connections in the pgx connection pool. Increase for high-concurrency deployments. |

## OIDC / Identity

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_ISSUER` | — | Yes (prod) | The OIDC issuer URL. Must be `https://` in production. Embedded in all issued tokens (`iss` claim) and the discovery document. Example: `https://auth.sin.to` |
| `SINAUTH_SITE_URL` | — | No | Base URL of the main SIN site. Used as a fallback allowed CORS origin if `SINAUTH_ALLOWED_ORIGINS` is not set. Example: `https://sin.to` |
| `SINAUTH_ALLOWED_ORIGINS` | — | No | Comma-separated list of CORS allowed origins. Example: `https://sin.to,https://apiguard.sin.to` |

## Token signing (RSA)

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_SIGNING_KEY_PATH` | — | Yes (prod) | Absolute path to the PEM-encoded RSA-2048 private key file. If the file does not exist at startup, sinauth generates a new key and writes it to this path. Example: `/etc/sinauth/keys/sinauth.pem` |
| `SINAUTH_SIGNING_KEY_ID` | `default` | No | Key ID embedded in the JWT `kid` header and the JWKS response. Change this when rotating keys. Example: `sinauth-1` |

## Token TTLs

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_ACCESS_TOKEN_TTL` | `1h` | No | Lifetime of access tokens. Accepts Go duration strings (`1h`, `30m`, `15m`). Shorter is more secure; platforms cache the JWKS so verification is local. |
| `SINAUTH_ID_TOKEN_TTL` | `5m` | No | Lifetime of ID tokens. ID tokens are used once at login to establish a session in the platform — 5 minutes is intentionally short. |
| `SINAUTH_REFRESH_TOKEN_TTL` | `720h` | No | Lifetime of refresh tokens (30 days by default). Stored as SHA-256 hashes in PostgreSQL; can be revoked individually. |

## Security

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_BCRYPT_COST` | `12` | No | Bcrypt work factor for hashing user passwords. 12 is the recommended minimum for 2024+. Higher values increase security but also increase CPU time per login (~250ms at cost 12 on modern hardware). |
| `SINAUTH_TRUSTED_PROXIES` | — | No | Comma-separated list of trusted reverse proxy IP addresses. When set, sinauth reads the real client IP from the `X-Forwarded-For` header for rate limiting purposes. Example: `10.0.0.1,10.0.0.2` |

## Social OAuth — Google

| Variable | Default | Required | Description |
|---|---|---|---|
| `GOOGLE_CLIENT_ID` | — | No | Google OAuth2 client ID. Leave empty to disable Google login. |
| `GOOGLE_CLIENT_SECRET` | — | No | Google OAuth2 client secret. |
| `GOOGLE_REDIRECT_URI` | — | No | Must match the redirect URI registered in the Google Cloud Console. Example: `https://auth.sin.to/oauth/callback/google` |

## Social OAuth — GitHub

| Variable | Default | Required | Description |
|---|---|---|---|
| `GITHUB_CLIENT_ID` | — | No | GitHub OAuth App client ID. Leave empty to disable GitHub login. |
| `GITHUB_CLIENT_SECRET` | — | No | GitHub OAuth App client secret. |
| `GITHUB_REDIRECT_URI` | — | No | Must match the callback URL registered in the GitHub OAuth App settings. Example: `https://auth.sin.to/oauth/callback/github` |

## Email (SMTP)

All SMTP variables are optional. When `SINAUTH_SMTP_HOST` is empty, email features (password reset, email verification) are disabled.

| Variable | Default | Required | Description |
|---|---|---|---|
| `SINAUTH_SMTP_HOST` | — | No | SMTP server hostname. Example: `smtp.sendgrid.net` |
| `SINAUTH_SMTP_PORT` | `587` | No | SMTP port. 587 for STARTTLS, 465 for TLS, 25 for unencrypted (not recommended). |
| `SINAUTH_SMTP_USERNAME` | — | No | SMTP authentication username. |
| `SINAUTH_SMTP_PASSWORD` | — | No | SMTP authentication password. |
| `SINAUTH_SMTP_FROM` | — | No | From address for outgoing emails. Example: `noreply@sin.to` |

## Minimum production configuration

```bash
SINAUTH_ISSUER=https://auth.sin.to
SINAUTH_DB_URL=postgres://sinauth:secret@db:5432/sinauth?sslmode=require
SINAUTH_SIGNING_KEY_PATH=/etc/sinauth/keys/sinauth.pem
SINAUTH_SIGNING_KEY_ID=sinauth-1
SINAUTH_SITE_URL=https://sin.to
SINAUTH_ALLOWED_ORIGINS=https://sin.to,https://apiguard.sin.to
```
