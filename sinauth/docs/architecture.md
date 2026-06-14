# Architecture

sinauth is a self-contained OIDC Authorization Server written in pure Go. It has no runtime dependencies beyond a PostgreSQL database — no Redis, no message queue, no external cache.

## Role in the SIN ecosystem

sinauth is the single identity plane for all SIN platforms. Each platform is registered as an OAuth2 client. When a user logs in to any SIN platform, they are redirected to sinauth, authenticate once, and receive tokens. Subsequent logins to other platforms within the same SSO session skip the login form entirely.

```
Browser ──► Platform A ──► sinauth ──► PostgreSQL
               ▲               │
               └───────────────┘
               (tokens returned)
```

## Components

### Keys Manager (`internal/keys`)

Loads an RSA-2048 private key from a PEM file at startup (or generates one if the file does not exist). Exposes the private key for token signing and the public key for JWKS export. Thread-safe via `sync.RWMutex`. The key ID (`kid`) is configured via `SINAUTH_SIGNING_KEY_ID`.

### Token Issuer (`internal/token`)

Signs access tokens and ID tokens with RS256. Both token types are standard JWTs. The issuer embeds `kid` in the JWT header so that verifiers can select the correct public key from the JWKS response.

### Token Verifier (`internal/token`)

Validates bearer tokens on protected endpoints. Checks signature, expiry, issuer, and audience.

### Token Store (`internal/token`)

Persists refresh tokens (as SHA-256 hashes) and authorization codes in PostgreSQL. Supports atomic revocation and expiry checks.

### OAuth Clients (`internal/client`)

CRUD operations on the `oauth_clients` table. Each registered platform has a `client_id`, optional `client_secret_hash`, `redirect_uris`, `allowed_scopes`, and a `require_pkce` flag (always true).

### Authorization Codes (`migrations/004_authorization_codes.sql`)

Short-lived (5-minute), one-time-use codes stored in `authorization_codes`. Contain the PKCE `code_challenge`, requested scopes, nonce, and user ID. Consumed atomically on token exchange.

### Consent (`internal/consent`)

Records which scopes a user has previously granted to a client in `oauth_consents`. If all requested scopes were previously consented, the consent screen is skipped.

### SSO Sessions (`internal/session`)

A session cookie (`sinauth_session`) is set on the browser after login. The session ID maps to a row in `sso_sessions` with a configurable TTL. As long as the session is valid, subsequent authorization requests for any client skip the login form.

### Discovery / OIDC (`internal/oidc`)

Builds the `/.well-known/openid-configuration` document and JWKS response from live configuration.

### API Server (`internal/api`)

Standard library `net/http` multiplexer. Middleware chain: CORS → MaxBodySize → Logger → global RateLimit (120 req/min) → route handlers. Auth endpoints additionally apply a stricter 5 req/min rate limit.

## Authorization Code + PKCE Flow

```
Browser / Platform Client                sinauth                  PostgreSQL
─────────────────────────────────────────────────────────────────────────────

1. Generate code_verifier (random 64 bytes, base64url)
   Compute code_challenge = BASE64URL(SHA-256(code_verifier))

2. GET /oauth/authorize
   ?response_type=code
   &client_id=community
   &redirect_uri=https://sin.to/auth/callback
   &scope=openid profile email
   &state=<random>
   &code_challenge=<challenge>
   &code_challenge_method=S256
                                ──► Validate client, redirect_uri, scopes
                                    Check SSO session cookie
                                    If no session → show login form
                                    POST /oauth/authorize (credentials)
                                    Create SSO session ──────────────────► INSERT sso_sessions
                                    Check consent ──────────────────────► SELECT oauth_consents
                                    If new scopes → show consent screen
                                    Store auth code ─────────────────────► INSERT authorization_codes
3.                              ◄── 302 redirect_uri?code=<code>&state=<state>

4. POST /oauth/token
   grant_type=authorization_code
   code=<code>
   redirect_uri=...
   code_verifier=<verifier>
   client_id=community
                                ──► Load auth code ──────────────────────► SELECT authorization_codes
                                    Verify PKCE: SHA-256(verifier)==challenge
                                    Mark code used ──────────────────────► UPDATE authorization_codes SET used=true
                                    Issue access token (RS256 JWT, 1h)
                                    Issue ID token     (RS256 JWT, 5min)
                                    Issue refresh token (opaque, 30d)────► INSERT refresh_tokens
5.                              ◄── { access_token, id_token, refresh_token, token_type, expires_in }

6. GET /oauth/userinfo
   Authorization: Bearer <access_token>
                                ──► Verify token signature + expiry
                                    Return { sub, email, name, picture }
```

## Database Tables

| Table | Purpose |
|---|---|
| `users` | User accounts — UUID PK, username, email, password_hash (bcrypt), avatar_url |
| `sso_sessions` | Browser SSO sessions — maps session ID to user, expires_at |
| `oauth_clients` | Registered platforms — client_id, redirect_uris, allowed_scopes, require_pkce |
| `authorization_codes` | One-time auth codes — code, PKCE challenge, scopes, 5-min TTL |
| `refresh_tokens` | Long-lived tokens (stored as SHA-256 hash) — revocable, 30-day TTL |
| `oauth_consents` | Per-user per-client scope grants — skip consent on repeat login |
| `totp_credentials` | TOTP MFA secrets per user |
| `audit_log` | Immutable record of auth events — actor, event_type, IP, metadata |

## How platforms verify tokens

Platforms do not need to call sinauth on every request. They verify tokens locally:

1. Fetch `https://auth.sin.to/.well-known/jwks.json` at startup (cache for 1 hour — `Cache-Control: public, max-age=3600`).
2. On each request, parse the JWT header to read `kid`.
3. Select the matching JWK from the cached set.
4. Verify the RS256 signature using the public key.
5. Check `exp`, `iss` (`https://auth.sin.to`), and `aud` (the platform's own `client_id`).

This design means platforms can verify millions of tokens per second without contacting sinauth, and key rotation is transparent — sinauth publishes the new key in JWKS before retiring the old one.

## No external dependencies

The entire server is: Go standard library + `pgx` (PostgreSQL driver) + `golang-jwt/jwt` (RS256 signing) + `cobra` (CLI). No Redis, no external cache, no message queue. All state lives in PostgreSQL, which is already required by every SIN platform.
