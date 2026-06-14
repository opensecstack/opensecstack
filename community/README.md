# SIN Community

An open-source developer community platform — posts, comments, tags, notifications, and more.

[![CI](https://github.com/opensecstack/community/actions/workflows/ci.yml/badge.svg)](https://github.com/opensecstack/community/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

SIN is a dev.to-inspired publishing platform for the OpenSecStack ecosystem. Operators and developers share post-mortems, detection recipes, NIS2 guides, and CSAF advisory write-ups — tagged, searchable, and optionally integrated with CITADEL for tamper evidence.

---

## Tech Stack

| Layer      | Technology                          |
|------------|-------------------------------------|
| Backend    | Go 1.25                             |
| Database   | PostgreSQL 16                       |
| Search     | Meilisearch v1.10                   |
| Frontend   | React + TypeScript + Vite           |
| Runtime    | Docker / Docker Compose             |

---

## Quick Start (Development)

```bash
git clone https://github.com/opensecstack/community.git
cd community
cp .env.example .env          # edit secrets before proceeding
cp web/.env.example web/.env  # set VITE_VAPID_PUBLIC_KEY
docker compose -f docker-compose.dev.yml up
```

| Service           | URL                        |
|-------------------|----------------------------|
| API               | http://localhost:8090      |
| Frontend (Vite)   | http://localhost:5173      |
| Meilisearch       | http://localhost:7700      |

The dev compose file seeds a default admin account via `COMMUNITY_USERS`. The development default is username `admin`, password `admin`. Change this before exposing the service to any network.

---

## Environment Variables

All variables consumed by the application are listed below. Variables without a `COMMUNITY_` prefix are used directly by the Go binary as shown in `internal/config/config.go`. See `.env.example` for a fully annotated template.

### Server

| Variable              | Default         | Required | Description                                                    |
|-----------------------|-----------------|----------|----------------------------------------------------------------|
| `COMMUNITY_HTTP_ADDR` | `:8090`         | No       | TCP address the HTTP server listens on.                        |
| `COMMUNITY_NODE`      | `community-0`   | No       | Logical node name for log aggregation and multi-node setups.   |
| `COMMUNITY_DEV_MODE`  | `false`         | No       | Disables secret validation checks. Never set `true` in production. |

### Database

| Variable                | Default | Required | Description                                              |
|-------------------------|---------|----------|----------------------------------------------------------|
| `COMMUNITY_DB_URL`      | —       | Yes      | PostgreSQL connection string. Required outside dev mode. |
| `COMMUNITY_DB_MAX_CONNS`| `16`    | No       | Maximum connections in the pgx connection pool.          |

### Authentication

**[sinauth](../sinauth/docs/integration/community.md) SSO is the primary, recommended way in.** "Continue with SIN" is the default button on the Login and Register pages — OAuth 2.0 / OIDC, authorization code + PKCE, via the server-side flow `GET /api/v1/auth/sinauth` → sinauth authorize → OAuth callback. A first sinauth login auto-provisions a Community account; an existing account is linked by verified email. sinauth also provides TOTP MFA and social login (Google, GitHub) centrally.

Because Community is the public hub, it **also** keeps a native account system as a fallback: email/password registration (Login, Register, email verification, password reset) with bcrypt + server-side pepper, plus optional GitHub/Google OAuth. After any path succeeds, Community issues its own HMAC-signed session JWT (see env vars below).

The enabled methods are advertised at `GET /api/v1/auth/methods`, which drives the buttons the frontend renders. In an integrated SIN deployment, set `COMMUNITY_NATIVE_AUTH=false` to disable native email/password entirely and make sinauth SSO the only login — matching the SSO-only dashboards (e.g. APIGuard, OpenScrub).

| Variable                   | Default     | Required | Description                                                              |
|----------------------------|-------------|----------|--------------------------------------------------------------------------|
| `COMMUNITY_NATIVE_AUTH`    | `true`      | No       | When `false`, native email/password endpoints return 403 and only sinauth SSO is offered. |
| `SINAUTH_CLIENT_ID`        | —           | No*      | OAuth client ID registered in sinauth. Required to enable "Continue with SIN". |
| `SINAUTH_CLIENT_SECRET`    | —           | No       | OAuth client secret (if the sinauth client is confidential).             |
| `SINAUTH_URL`              | `http://localhost:8100` | No | sinauth base URL (e.g. `https://auth.sin.to`).                |
| `SINAUTH_CALLBACK_URL`     | `https://sin.to/api/v1/auth/sinauth/callback` | No | OAuth redirect URI registered for this client. |
| `COMMUNITY_JWT_SECRET`     | —           | Yes      | HMAC secret for signing session JWTs. Must be >= 32 bytes in production. |
| `COMMUNITY_JWT_ISSUER`     | `community` | No       | Value of the `iss` claim in issued tokens.                               |
| `COMMUNITY_TOKEN_TTL`      | `12h`       | No       | Access token lifetime as a Go duration string (e.g. `12h`, `24h`).      |
| `COMMUNITY_PASSWORD_PEPPER`| —           | Yes**    | Server-side pepper appended before bcrypt hashing. Must not contain the dev sentinel in production. |

\* Required only to enable sinauth SSO. \*\* Required only when native auth is enabled.

### Registration

| Variable                        | Default | Required | Description                                                                                    |
|---------------------------------|---------|----------|------------------------------------------------------------------------------------------------|
| `COMMUNITY_INVITE_ONLY`         | `false` | No       | When `true`, new accounts require an invite code.                                              |
| `COMMUNITY_ALLOWED_EMAIL_DOMAINS` | —     | No       | Comma-separated list of permitted email domains. Empty allows all domains.                     |
| `COMMUNITY_USERS`               | —       | No       | Bootstrap accounts. Comma-separated `username:role:bcrypt-hash` entries. Roles: `viewer`, `author`, `moderator`, `admin`. |

### Site

| Variable   | Default               | Required | Description                                              |
|------------|-----------------------|----------|----------------------------------------------------------|
| `SITE_URL` | `http://localhost:5173` | No     | Public-facing base URL. Used in emails and OAuth redirects. |

### Uploads

| Variable     | Default      | Required | Description                                      |
|--------------|--------------|----------|--------------------------------------------------|
| `UPLOAD_DIR` | `./uploads`  | No       | Filesystem path where uploaded images are stored. Mount as a persistent volume in production. |

### Search

| Variable           | Default                  | Required | Description                                        |
|--------------------|--------------------------|----------|----------------------------------------------------|
| `MEILISEARCH_URL`  | `http://localhost:7700`  | No       | Base URL of the Meilisearch instance.              |
| `MEILISEARCH_KEY`  | —                        | Yes      | API key used to authenticate with Meilisearch. Should match `MEILI_MASTER_KEY`. |

### Email (SMTP)

Leave `SMTP_HOST` empty to disable all outgoing email, including digest emails.

| Variable        | Default            | Required | Description                               |
|-----------------|--------------------|----------|-------------------------------------------|
| `SMTP_HOST`     | —                  | No       | SMTP server hostname. Empty disables mail.|
| `SMTP_PORT`     | `587`              | No       | SMTP port (typically 587 for STARTTLS).   |
| `SMTP_USERNAME` | —                  | No       | SMTP authentication username.             |
| `SMTP_PASSWORD` | —                  | No       | SMTP authentication password.             |
| `SMTP_FROM`     | `noreply@sin.to`   | No       | Sender address used in outgoing messages. |
| `DIGEST_ENABLED`| `true`             | No       | Enable or disable weekly digest emails.   |

### GitHub OAuth

Create an OAuth App at https://github.com/settings/developers.

| Variable                | Default                                         | Required | Description                          |
|-------------------------|-------------------------------------------------|----------|--------------------------------------|
| `GITHUB_CLIENT_ID`      | —                                               | No       | GitHub OAuth App client ID.          |
| `GITHUB_CLIENT_SECRET`  | —                                               | No       | GitHub OAuth App client secret.      |
| `GITHUB_CALLBACK_URL`   | `https://sin.to/api/v1/auth/github/callback`    | No       | Redirect URL registered in GitHub.   |

### Google OAuth

Create credentials at https://console.cloud.google.com/apis/credentials.

| Variable                | Default                                         | Required | Description                          |
|-------------------------|-------------------------------------------------|----------|--------------------------------------|
| `GOOGLE_CLIENT_ID`      | —                                               | No       | Google OAuth client ID.              |
| `GOOGLE_CLIENT_SECRET`  | —                                               | No       | Google OAuth client secret.          |
| `GOOGLE_REDIRECT_URI`   | `https://sin.to/api/v1/auth/google/callback`    | No       | Redirect URI registered in Google.   |

### Citadel Integration

CITADEL emits tamper-evident evidence records when posts are published. Leave `COMMUNITY_CITADEL_API_URL` empty to disable the integration entirely.

| Variable                    | Default       | Required | Description                                                                 |
|-----------------------------|---------------|----------|-----------------------------------------------------------------------------|
| `COMMUNITY_CITADEL_API_URL` | —             | No       | Base URL of the Citadel API. Empty disables the integration.                |
| `COMMUNITY_CITADEL_KEY_ID`  | `community-1` | No       | Key identifier sent in Citadel requests.                                    |
| `COMMUNITY_CITADEL_HMAC_SECRETS` | —        | No       | Comma-separated HMAC secrets for verifying inbound Citadel webhook payloads.|
| `COMMUNITY_CITADEL_DRY_RUN` | `true`        | No       | When `true`, Citadel calls are logged but not sent. Set `false` in production when Citadel is fully configured. |

---

## Production Deployment

The production compose file builds a multi-stage Docker image that bundles both the Go binary and the React SPA into a single container.

```bash
cp .env.example .env   # fill in all required production values
VERSION=1.2.3 docker compose up -d --build
```

The `VERSION` build argument is injected into the binary at compile time via `-ldflags`. It defaults to `dev` when not set.

Ensure the following before going live:

- `COMMUNITY_DEV_MODE` is `false` or unset.
- `COMMUNITY_JWT_SECRET` is at least 32 bytes of random data.
- `COMMUNITY_PASSWORD_PEPPER` does not contain the dev sentinel string.
- `COMMUNITY_CITADEL_DRY_RUN` is set to `false` if Citadel is configured.
- `uploads` and `meilidata` volumes are backed by persistent storage.

---

## Project Structure

```
cmd/server/         — application entrypoint
internal/api/       — HTTP handlers and middleware
internal/db/        — migrations and connection pool
internal/config/    — environment-based configuration loader
internal/auth/      — JWT helpers and token management
internal/email/     — email templates and dispatch
internal/search/    — Meilisearch integration
web/                — React/TypeScript/Vite frontend
docs/               — operator guides
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, branch conventions, and the pull request process.

---

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
