# Admin Guide

This guide covers sinauth's administrative operations: managing OAuth clients (platforms), managing users, and reading the audit log.

## Registering a new OAuth client (platform)

Each SIN platform must be registered as an OAuth client in sinauth before it can participate in the SSO flow.

### Required fields

| Field | Type | Description |
|---|---|---|
| `client_id` | string | Unique identifier for the platform. Use a short lowercase slug, e.g. `community`, `apiguard`, `irflow`. |
| `name` | string | Human-readable display name shown on the consent screen. |
| `redirect_uris` | string[] | Exact list of allowed redirect URIs. The authorization request's `redirect_uri` must be in this list. Include both local dev URIs during development. |
| `allowed_scopes` | string[] | Scopes this client is allowed to request. Default: `["openid", "profile", "email"]`. |
| `require_pkce` | bool | Must be `true`. sinauth enforces PKCE for all clients — this field documents the intent. |
| `is_confidential` | bool | `true` if the client has a backend that can keep a secret (confidential client). `false` for SPAs and mobile apps (public client). |

### Optional fields

| Field | Type | Description |
|---|---|---|
| `client_secret_hash` | string | Pre-hashed client secret (bcrypt). Only relevant for confidential clients. |
| `logo_url` | string | URL to the platform's logo, shown on the consent screen. |
| `grant_types` | string[] | Defaults to `["authorization_code", "refresh_token"]`. |

### Registering via the Admin API

```bash
curl -X POST https://auth.sin.to/api/v1/admin/clients \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "community",
    "name": "SIN Community",
    "redirect_uris": [
      "https://sin.to/auth/callback",
      "http://localhost:5174/auth/callback"
    ],
    "allowed_scopes": ["openid", "profile", "email", "offline_access"],
    "require_pkce": true,
    "is_confidential": false
  }'
```

### Registering via direct SQL (bootstrapping)

During initial setup, before any admin token exists, you can insert clients directly:

```sql
INSERT INTO oauth_clients (
    client_id, name, redirect_uris, allowed_scopes,
    require_pkce, is_confidential
) VALUES (
    'community',
    'SIN Community',
    ARRAY['https://sin.to/auth/callback', 'http://localhost:5174/auth/callback'],
    ARRAY['openid', 'profile', 'email', 'offline_access'],
    true,
    false
);
```

### PKCE requirement

All clients must use PKCE (`code_challenge_method=S256`). sinauth will reject authorization requests without a valid `code_challenge`. There are no exceptions — even confidential clients with a `client_secret` must use PKCE.

### Listing clients

```bash
curl https://auth.sin.to/api/v1/admin/clients \
  -H "Authorization: Bearer <admin_access_token>"
```

### Deleting a client

Deleting a client cascades: authorization codes and refresh tokens associated with the client are also deleted.

```bash
curl -X DELETE https://auth.sin.to/api/v1/admin/clients/<client-uuid> \
  -H "Authorization: Bearer <admin_access_token>"
```

## Deactivating users

Deactivated users cannot log in. Their data (tokens, consents, audit log entries) is preserved.

```bash
curl -X POST https://auth.sin.to/api/v1/admin/users/<user-uuid>/deactivate \
  -H "Authorization: Bearer <admin_access_token>"
```

To re-activate, set `deactivated_at = NULL` directly in the database (no API endpoint in v1.0):

```sql
UPDATE users SET deactivated_at = NULL WHERE id = '<user-uuid>';
```

## Viewing the audit log

The `audit_log` table records all significant auth events. Query it directly via PostgreSQL:

```sql
-- Recent failed logins
SELECT actor, ip_address, metadata, created_at
FROM audit_log
WHERE event_type = 'login.failure'
ORDER BY created_at DESC
LIMIT 50;

-- All tokens issued for a specific user
SELECT client_id, created_at
FROM audit_log
WHERE event_type = 'token.issued' AND actor = 'jane'
ORDER BY created_at DESC;

-- Activity from a suspicious IP
SELECT event_type, actor, client_id, created_at
FROM audit_log
WHERE ip_address = '1.2.3.4'
ORDER BY created_at DESC;
```

### Audit event types

| Event type | Description |
|---|---|
| `login.success` | User authenticated successfully |
| `login.failure` | Wrong password or unknown username |
| `token.issued` | Authorization code was exchanged for tokens |
| `token.revoked` | Refresh token was revoked |
| `client.created` | New OAuth client registered |
| `user.deactivated` | User account deactivated |
| `user.registered` | New user account created |
| `password.reset` | Password was reset via email token |
