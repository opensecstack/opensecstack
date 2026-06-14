# Integrating SIN Community with sinauth

SIN Community is the developer knowledge hub platform at `sin.to`. This guide covers the specific sinauth configuration for Community.

## Client registration

```json
{
  "client_id": "community",
  "name": "SIN Community",
  "redirect_uris": [
    "https://sin.to/auth/callback",
    "http://localhost:5174/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false,
  "logo_url": "https://sin.to/logo.svg"
}
```

Community is a **public client** (no client secret) — it runs as a browser-based SPA or a Next.js app where secrets cannot be kept safely. PKCE provides the security guarantee instead.

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the user |
| `profile` | Display the user's name and avatar in posts and comments |
| `email` | Required for notification emails and account recovery |
| `offline_access` | Keeps the user logged in across browser sessions without re-authentication |

## Environment configuration (Community side)

```env
SINAUTH_ISSUER=https://auth.sin.to
SINAUTH_CLIENT_ID=community
SINAUTH_REDIRECT_URI=https://sin.to/auth/callback
SINAUTH_SCOPES=openid profile email offline_access
```

## Claim mapping

| sinauth claim | Community field | Notes |
|---|---|---|
| `sub` | `users.sinauth_id` | Primary foreign key — use UUID, not email |
| `email` | `users.email` | Sync on login; do not use as PK |
| `name` | `users.display_name` | Set on first login; user can override in profile |
| `picture` | `users.avatar_url` | Set on first login; user can override |
| `email_verified` | `users.email_verified` | Gate on posting if false |

## First login provisioning

On the first callback after a new user authenticates, Community creates the user record:

```typescript
const claims = await verifyIDToken(tokens.id_token);

const user = await db.upsertUser({
    sinauth_id: claims.sub,
    email: claims.email,
    display_name: claims.name,
    avatar_url: claims.picture,
    email_verified: claims.email_verified,
    role: 'member',  // default role
});
```

## Logout

Redirect to sinauth's end-session endpoint and clear the local session:

```
https://auth.sin.to/oauth/endsession
  ?post_logout_redirect_uri=https://sin.to/
  &id_token_hint=<id_token>
```

Community should clear its own session cookie before redirecting, so the user is not briefly re-logged-in by a stale local session.

## See also

- [Generic integration guide](custom.md) — full code examples for the PKCE flow
- [Concepts: Tokens](../concepts/tokens.md) — ID token claims reference
- [Concepts: Scopes](../concepts/scopes.md) — scope definitions
