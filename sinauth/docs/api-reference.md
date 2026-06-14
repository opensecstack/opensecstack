# API Reference

Base URL (production): `https://auth.sin.to`
Base URL (local dev): `http://localhost:8100`

All responses are JSON unless noted otherwise. Error responses always include an `error` field and optionally an `error_description` field following RFC 6749.

---

## OIDC Discovery

### `GET /.well-known/openid-configuration`

Returns the OpenID Connect discovery document. Clients should read this once at startup and cache for 1 hour (`Cache-Control: public, max-age=3600`).

**Response `200 OK`**

```json
{
  "issuer": "https://auth.sin.to",
  "authorization_endpoint": "https://auth.sin.to/oauth/authorize",
  "token_endpoint": "https://auth.sin.to/oauth/token",
  "userinfo_endpoint": "https://auth.sin.to/oauth/userinfo",
  "jwks_uri": "https://auth.sin.to/.well-known/jwks.json",
  "end_session_endpoint": "https://auth.sin.to/oauth/endsession",
  "revocation_endpoint": "https://auth.sin.to/oauth/token/revoke",
  "introspection_endpoint": "https://auth.sin.to/oauth/token/introspect",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "picture"]
}
```

---

### `GET /.well-known/jwks.json`

Returns the JSON Web Key Set containing the active RSA public key. Platforms use this to verify token signatures. Cache for 1 hour; re-fetch on `kid` mismatch.

**Response `200 OK`**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "sinauth-1",
      "n": "<base64url-encoded modulus>",
      "e": "AQAB"
    }
  ]
}
```

---

## OAuth2 / OIDC Protocol Endpoints

### `GET /oauth/authorize`

Initiates the Authorization Code + PKCE flow. Redirect the user's browser here.

**Query parameters**

| Parameter | Required | Description |
|---|---|---|
| `response_type` | Yes | Must be `code`. |
| `client_id` | Yes | The registered client ID of the platform. |
| `redirect_uri` | Yes | Must exactly match one of the client's registered redirect URIs. |
| `scope` | Yes | Space-separated scopes. Must include `openid`. Example: `openid profile email`. |
| `state` | Recommended | Opaque value echoed back in the redirect. Use to prevent CSRF. |
| `code_challenge` | Yes | BASE64URL(SHA-256(`code_verifier`)). Required — PKCE is mandatory. |
| `code_challenge_method` | Yes | Must be `S256`. |
| `nonce` | Recommended | Random value embedded in the ID token to bind it to the session. |

**Behavior**

- If the user has a valid SSO session, the login form is skipped.
- If consent was previously granted for all requested scopes, the consent screen is skipped.
- On success: `302` redirect to `redirect_uri?code=<code>&state=<state>`. The code is valid for 5 minutes and can be used once.
- On error: `302` redirect to `redirect_uri?error=<code>&error_description=<text>&state=<state>`.

**Error codes**: `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`.

---

### `POST /oauth/token`

Exchanges an authorization code or refresh token for tokens.

**Request** (`application/x-www-form-urlencoded`)

#### Grant: `authorization_code`

| Parameter | Required | Description |
|---|---|---|
| `grant_type` | Yes | `authorization_code` |
| `code` | Yes | The authorization code from the redirect. |
| `redirect_uri` | Yes | Must match the redirect URI used in the authorization request. |
| `client_id` | Yes | The client's registered client ID. |
| `code_verifier` | Yes | The original PKCE code verifier. sinauth verifies SHA-256(`code_verifier`) == stored `code_challenge`. |
| `client_secret` | Cond. | Required for confidential clients. Send via `Authorization: Basic` header (preferred) or body. |

#### Grant: `refresh_token`

| Parameter | Required | Description |
|---|---|---|
| `grant_type` | Yes | `refresh_token` |
| `refresh_token` | Yes | The opaque refresh token. |
| `client_id` | Yes | Must match the client that was issued the refresh token. |
| `scope` | No | Request a subset of the original scopes. Cannot expand scope. |

**Response `200 OK`**

```json
{
  "access_token": "<RS256 JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "<RS256 JWT>",
  "refresh_token": "<opaque token>",
  "scope": "openid profile email"
}
```

`id_token` is only present when `openid` is in the granted scopes.
`refresh_token` is only present when `offline_access` is in the granted scopes.

**Error `400 Bad Request`**

```json
{ "error": "invalid_grant", "error_description": "authorization code is expired or already used" }
```

---

### `GET /oauth/userinfo` and `POST /oauth/userinfo`

Returns claims about the authenticated user. Requires a valid access token.

**Request header**: `Authorization: Bearer <access_token>`

**Response `200 OK`**

Claims returned depend on the scopes granted when the access token was issued:

| Scope | Claims returned |
|---|---|
| `openid` | `sub` |
| `profile` | `name`, `picture` |
| `email` | `email`, `email_verified` |

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true,
  "name": "Jane Doe",
  "picture": "https://..."
}
```

**Error `401 Unauthorized`**: token missing, expired, or invalid signature.

---

### `POST /oauth/token/revoke`

Revokes a refresh token. Follows RFC 7009.

**Request** (`application/x-www-form-urlencoded`)

| Parameter | Required | Description |
|---|---|---|
| `token` | Yes | The refresh token to revoke. |
| `client_id` | Yes | The client that owns the token. |

**Response**: `200 OK` (always — per RFC 7009, revocation of an unknown token is not an error).

---

### `POST /oauth/token/introspect`

Returns metadata about a token. Follows RFC 7662. Intended for resource servers that cannot verify RS256 locally.

**Request** (`application/x-www-form-urlencoded`)

| Parameter | Required | Description |
|---|---|---|
| `token` | Yes | The access token or refresh token to introspect. |
| `client_id` | Yes | The requesting client. |

**Response `200 OK` — active token**

```json
{
  "active": true,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "client_id": "community",
  "scope": "openid profile email",
  "exp": 1700000000,
  "iat": 1699996400,
  "iss": "https://auth.sin.to"
}
```

**Response `200 OK` — inactive/unknown token**

```json
{ "active": false }
```

---

### `GET /oauth/endsession`

Terminates the user's SSO session (single logout). Clears the session cookie and invalidates the session in the database.

**Query parameters**

| Parameter | Required | Description |
|---|---|---|
| `post_logout_redirect_uri` | No | URL to redirect to after logout. Must be pre-registered or match the client's site URL. |
| `id_token_hint` | No | The user's ID token — used to identify which session to end. |
| `state` | No | Echoed back in the redirect. |

**Response**: `302` redirect to `post_logout_redirect_uri` or the sinauth login page.

---

## User Auth Endpoints

These endpoints are used by sinauth's own login UI. Rate limited to **5 requests per minute per IP**.

### `POST /api/v1/auth/login`

**Request** (`application/json`)

```json
{ "username": "jane", "password": "hunter2" }
```

Sets the `sinauth_session` cookie on success. Returns `400` with `{"error": "invalid_credentials"}` on failure.

### `POST /api/v1/auth/register`

**Request** (`application/json`)

```json
{ "username": "jane", "email": "jane@example.com", "password": "hunter2" }
```

Creates a new user account. Returns `409` if username or email is already taken.

### `POST /api/v1/auth/forgot-password`

**Request** (`application/json`)

```json
{ "email": "jane@example.com" }
```

Sends a password-reset email if the address is registered. Always returns `200` to prevent email enumeration.

### `POST /api/v1/auth/reset-password`

**Request** (`application/json`)

```json
{ "token": "<reset token from email>", "password": "newpassword123" }
```

---

## Admin Endpoints

Require a valid admin access token (`Authorization: Bearer <token>`).

### `GET /api/v1/admin/clients`

Lists all registered OAuth clients.

### `POST /api/v1/admin/clients`

Registers a new OAuth client.

**Request** (`application/json`)

```json
{
  "client_id": "apiguard",
  "name": "APIGuard",
  "redirect_uris": ["https://apiguard.sin.to/auth/callback"],
  "allowed_scopes": ["openid", "profile", "email"],
  "require_pkce": true,
  "is_confidential": false
}
```

### `DELETE /api/v1/admin/clients/{id}`

Deletes an OAuth client by its database UUID.

### `GET /api/v1/admin/users`

Lists all user accounts.

### `POST /api/v1/admin/users/{id}/deactivate`

Deactivates a user account. The user cannot log in but their data is preserved.

---

## Health Endpoints

### `GET /api/v1/health`

Liveness probe. Returns `200` if the process is running.

```json
{ "status": "ok" }
```

### `GET /api/v1/ready`

Readiness probe. Returns `200` only if the database connection is healthy.

```json
{ "status": "ok" }
```

Returns `503` if the database is unreachable.
