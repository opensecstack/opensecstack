# Tokens

sinauth issues three types of tokens. Two are RS256-signed JWTs; one is an opaque random string.

## Access Token

**Format**: RS256-signed JWT
**Lifetime**: 1 hour (configurable via `SINAUTH_ACCESS_TOKEN_TTL`)
**Purpose**: Authorizing calls to protected APIs on SIN platforms

### Claims

| Claim | Type | Description |
|---|---|---|
| `sub` | string (UUID) | Subject — the user's unique ID in sinauth. Stable across sessions and platforms. |
| `iss` | string | Issuer — always `https://auth.sin.to` (or the configured issuer). |
| `aud` | string | Audience — the `client_id` of the platform the token was issued for. |
| `exp` | number | Expiry time (Unix timestamp). |
| `iat` | number | Issued-at time (Unix timestamp). |
| `nbf` | number | Not-before time — same as `iat`. |
| `jti` | string (UUID) | JWT ID — unique per token, for audit purposes. |
| `client_id` | string | The OAuth client (platform) that requested the token. Same value as `aud`. |
| `scope` | string[] | Array of granted scopes, e.g. `["openid", "profile", "email"]`. |

### Example payload

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://auth.sin.to",
  "aud": "community",
  "exp": 1700003600,
  "iat": 1700000000,
  "nbf": 1700000000,
  "jti": "a1b2c3d4-e5f6-...",
  "client_id": "community",
  "scope": ["openid", "profile", "email"]
}
```

### How platforms verify access tokens

1. Fetch `https://auth.sin.to/.well-known/jwks.json` at startup and cache for 1 hour.
2. Read `kid` from the JWT header.
3. Find the matching JWK in the cached set.
4. Verify the RS256 signature using the JWK's public key.
5. Check `exp > now()`, `iss == "https://auth.sin.to"`, `aud == <your client_id>`.

This verification is entirely local — no call to sinauth is required per request.

---

## ID Token

**Format**: RS256-signed JWT
**Lifetime**: 5 minutes (configurable via `SINAUTH_ID_TOKEN_TTL`)
**Purpose**: Authenticating the user at login time (OIDC)

The ID token is issued alongside the access token when the `openid` scope is granted. It is intended for the client application, not for API calls. Read it once at login to establish who the user is, then discard it.

### Claims

| Claim | Type | Scope required | Description |
|---|---|---|---|
| `sub` | string (UUID) | `openid` | Subject — the user's stable unique ID. |
| `iss` | string | `openid` | Issuer. |
| `aud` | string | `openid` | Audience — the client_id. |
| `exp` | number | `openid` | Expiry time. |
| `iat` | number | `openid` | Issued-at time. |
| `jti` | string | `openid` | JWT ID. |
| `azp` | string | `openid` | Authorized party — same as `aud` / `client_id`. |
| `nonce` | string | `openid` | The nonce from the authorization request. Verify this matches to prevent replay attacks. |
| `email` | string | `email` | User's email address. |
| `email_verified` | bool | `email` | Whether sinauth has verified the email address. |
| `name` | string | `profile` | User's display name. |
| `picture` | string | `profile` | URL to the user's avatar image. |

### Example payload

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://auth.sin.to",
  "aud": "community",
  "exp": 1700000300,
  "iat": 1700000000,
  "jti": "b2c3d4e5-f6a7-...",
  "azp": "community",
  "nonce": "random-nonce-value",
  "email": "jane@example.com",
  "email_verified": true,
  "name": "Jane Doe",
  "picture": "https://avatars.githubusercontent.com/u/12345"
}
```

---

## Refresh Token

**Format**: Opaque random string (not a JWT)
**Lifetime**: 30 days (configurable via `SINAUTH_REFRESH_TOKEN_TTL`)
**Purpose**: Obtaining new access tokens without re-authenticating the user

Refresh tokens are only issued when the `offline_access` scope is requested and granted.

### How refresh tokens work

The token itself is an opaque random string — it has no parseable structure. sinauth stores a `SHA-256` hash of the token in the `refresh_tokens` table alongside the associated user ID, client ID, scopes, and expiry.

When a platform calls `POST /oauth/token` with `grant_type=refresh_token`, sinauth:
1. Hashes the presented token.
2. Looks up the hash in the database.
3. Checks that it is not revoked and not expired.
4. Issues a new access token (and optionally a new refresh token).

### Revocation

Refresh tokens can be revoked at any time via `POST /oauth/token/revoke`. Once revoked, the `revoked` flag is set to `true` in the database and the token can no longer be used.

Refresh tokens are also revoked when:
- The associated user is deactivated.
- The associated OAuth client is deleted.
- The user explicitly logs out (`GET /oauth/endsession`).
