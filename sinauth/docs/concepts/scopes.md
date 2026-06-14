# Scopes

Scopes define what information an OAuth client is authorized to access. The user sees the requested scopes on the consent screen and can approve or deny them.

## Standard scopes

sinauth supports the four standard OIDC/OAuth2 scopes:

| Scope | ID token claims | UserInfo claims | Description |
|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `jti`, `azp`, `nonce` | `sub` | Required for all OIDC flows. Enables ID token issuance. Identifies the user with a stable UUID (`sub`). |
| `profile` | `name`, `picture` | `name`, `picture` | The user's display name and avatar URL. |
| `email` | `email`, `email_verified` | `email`, `email_verified` | The user's email address and whether sinauth has verified it. |
| `offline_access` | — (not in ID token) | — | Enables refresh token issuance. Without this scope, the session ends when the access token expires. Request this scope when you want to maintain a session across browser closes. |

## Requesting scopes

Scopes are requested as a space-separated string in the `scope` parameter of the authorization request:

```
/oauth/authorize?...&scope=openid%20profile%20email%20offline_access
```

## Scope requirements per platform

Different platforms need different scopes depending on what they display to the user:

| Platform | Minimum scopes | Notes |
|---|---|---|
| All platforms | `openid` | Required to identify the user |
| Platforms showing user's name/avatar | `openid profile` | |
| Platforms with user notifications | `openid profile email` | |
| Platforms with persistent sessions | `openid profile email offline_access` | Enables refresh token |

## Consent

The first time a user authorizes a specific client with a specific set of scopes, the consent screen is shown. The user approves the scopes and sinauth records the consent in the `oauth_consents` table. On subsequent logins with the same client and the same (or narrower) set of scopes, the consent screen is skipped automatically.

If a platform later requests additional scopes (e.g., adding `offline_access`), the consent screen is shown again for the new scopes only.

See [concepts/consent.md](consent.md) for the full consent flow.

## Custom scopes (planned v2.0)

v1.0 uses only the four standard scopes. Custom per-platform scopes (e.g., `apiguard:scan:read`) are planned for v2.0. These would allow sinauth to encode platform-specific permissions directly in the access token, eliminating the need for each platform to maintain its own roles table that maps `sub` to permissions.
