# Security

This document describes sinauth's security model, the rationale behind each design decision, and operational security guidelines.

## Token signing: RS256

All tokens (access tokens and ID tokens) are signed with RSA-2048 using the RS256 algorithm (RSASSA-PKCS1-v1_5 with SHA-256).

**Why RS256 over HS256:**

- The private key never leaves sinauth. Platforms verify tokens using the public key from the JWKS endpoint.
- A compromised platform cannot forge tokens — it only has the public key.
- Key rotation is transparent: sinauth publishes the new public key in JWKS; platforms re-fetch automatically on `kid` mismatch.

RSA-2048 provides ~112 bits of security strength, meeting NIST SP 800-57 recommendations through 2030.

## PKCE required for all clients

PKCE (Proof Key for Code Exchange, RFC 7636) is mandatory for all OAuth clients, including confidential clients with a `client_secret`. This prevents authorization code interception attacks:

1. Without PKCE, a malicious app that intercepts the authorization code (e.g., via a URL scheme on mobile) can exchange it for tokens.
2. With PKCE, the code is only useful to the party that generated the original `code_verifier` — the interceptor cannot use the code.

sinauth rejects authorization requests that do not include `code_challenge` and `code_challenge_method=S256`.

## Password hashing: bcrypt cost 12

User passwords are hashed with bcrypt at cost factor 12. At this cost, hashing one password takes approximately 250ms on modern server hardware, making offline brute-force attacks impractical even if the `users` table is leaked.

Cost 12 is the recommended minimum for 2024+. The cost is configurable via `SINAUTH_BCRYPT_COST` but should never be set below 12 in production.

## Token expiry

| Token | Default TTL | Rationale |
|---|---|---|
| Access token | 1 hour | Short enough to limit damage from token leakage. Platforms cache JWKS locally so verification is cheap even with short-lived tokens. |
| ID token | 5 minutes | ID tokens are used once at login to establish a session in the platform. A 5-minute window is sufficient; shorter reduces the window for replay attacks. |
| Refresh token | 30 days | Long-lived for user convenience, but stored as a SHA-256 hash in the database and can be revoked individually at any time. |

## Rate limiting

sinauth applies two levels of rate limiting, implemented in-process without Redis:

| Scope | Limit | Applied to |
|---|---|---|
| Global | 120 requests/minute per IP | All endpoints |
| Auth endpoints | 5 requests/minute per IP | `POST /api/v1/auth/login`, `POST /api/v1/auth/register`, `POST /api/v1/auth/forgot-password`, `POST /api/v1/auth/reset-password` |

Rate limiting is based on the real client IP. If sinauth is behind a trusted reverse proxy, set `SINAUTH_TRUSTED_PROXIES` to the proxy's IP so that `X-Forwarded-For` is used for IP resolution.

Exceeding the limit returns `429 Too Many Requests` with body `{"error": "too many requests"}`.

## Brute-force protection

The 5 req/min rate limit on login endpoints makes credential stuffing and brute-force attacks slow. At 5 attempts/minute, exhausting a 6-character lowercase password space would take centuries.

Additionally:
- bcrypt's computational cost (~250ms) makes parallel brute-force against a single account impractical even without rate limiting.
- Failed login events are written to the `audit_log` table with the actor, IP address, and timestamp, enabling detection and alerting.

## Authorization code security

Authorization codes are:
- Single-use: the first `POST /oauth/token` call marks the code `used=true` atomically. A second use returns `invalid_grant`.
- Short-lived: codes expire after 5 minutes.
- PKCE-bound: the `code_verifier` submitted at token exchange must produce the `code_challenge` stored with the code.
- Tied to the redirect URI: the `redirect_uri` at token exchange must exactly match the one used in the authorization request.

## Refresh token security

Refresh tokens are:
- Stored as `SHA-256(token)` in the database — the raw token is never persisted.
- Revocable via `POST /oauth/token/revoke` or the admin API.
- Scoped to a single client: a refresh token for `community` cannot be used to get tokens for `apiguard`.

## SSO session security

The SSO session cookie (`sinauth_session`) is:
- `HttpOnly`: not accessible to JavaScript.
- `Secure`: only sent over HTTPS (enforced in production).
- `SameSite=Lax`: mitigates CSRF for most cross-site scenarios.

Session IDs are cryptographically random (UUID v4).

## CORS

sinauth enforces an allowlist of CORS origins configured via `SINAUTH_ALLOWED_ORIGINS`. Browsers are blocked from making cross-origin requests to sinauth from unlisted origins.

## Audit log

All significant auth events are written to the `audit_log` table:

| Event type | Triggered by |
|---|---|
| `login.success` | Successful password login |
| `login.failure` | Wrong password |
| `token.issued` | Successful `/oauth/token` exchange |
| `token.revoked` | `POST /oauth/token/revoke` |
| `client.created` | Admin creates a new OAuth client |
| `user.deactivated` | Admin deactivates a user |

The audit log is append-only from the application's perspective (no `DELETE` or `UPDATE` path in the code). Retention and archival are handled at the database level.

## Responsible disclosure

If you discover a security vulnerability in sinauth, please report it privately:

**Email**: security@sin.to
**Response time**: 48 hours
**Disclosure policy**: coordinated — we will work with you to understand and patch the issue before any public disclosure.

Please do not open public GitHub issues for security vulnerabilities.
