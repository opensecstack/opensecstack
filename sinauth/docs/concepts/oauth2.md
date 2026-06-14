# OAuth 2.0

## What is OAuth 2.0?

OAuth 2.0 (RFC 6749) is an authorization framework that lets a user grant a third-party application limited access to their resources on another service — without sharing their credentials.

Classic example: a third-party app wants to read your Google Calendar. Instead of giving the app your Google password, Google asks you to approve specific permissions, then gives the app a token it can use to read your calendar. Your password never leaves Google.

In the SIN ecosystem, the pattern is the same: when you open a SIN platform (e.g., APIGuard), it asks sinauth for permission to know who you are. You log in to sinauth once, approve the scopes, and APIGuard receives a token — it never sees your password.

## The Authorization Code Flow

sinauth exclusively supports the Authorization Code flow. It is the most secure flow for web applications because the token is never exposed in the browser URL.

```
1. Platform redirects browser to sinauth:
   GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...

2. User authenticates at sinauth (login form).

3. sinauth redirects browser back to the platform:
   GET https://platform.sin.to/callback?code=<authorization_code>&state=...

4. Platform's backend exchanges the code for tokens (server-to-server):
   POST /oauth/token
   { grant_type: authorization_code, code: ..., redirect_uri: ..., ... }

5. sinauth returns tokens:
   { access_token, id_token, refresh_token, expires_in }
```

The authorization code in step 3 is short-lived (5 minutes) and single-use. Even if it is intercepted, it is useless without the PKCE `code_verifier` (see below).

## PKCE (Proof Key for Code Exchange)

PKCE (RFC 7636) is an extension to the Authorization Code flow that protects against authorization code interception. sinauth requires PKCE for all clients.

The flow:
1. The client generates a random `code_verifier` (64 random bytes, base64url-encoded).
2. The client computes `code_challenge = BASE64URL(SHA-256(code_verifier))`.
3. The client sends `code_challenge` and `code_challenge_method=S256` in the authorization request.
4. sinauth stores the `code_challenge` with the authorization code.
5. When the code is exchanged for tokens, the client sends the original `code_verifier`.
6. sinauth verifies: `SHA-256(code_verifier) == stored code_challenge`.

An attacker who intercepts the authorization code cannot exchange it — they don't have the `code_verifier`. See [concepts/pkce.md](pkce.md) for more detail.

## Scopes

Scopes are space-separated strings that define what the access token is authorized to do. The client requests scopes in the authorization request; the user approves them on the consent screen; the issued token's `scope` claim reflects what was granted.

sinauth supports:

| Scope | Grants access to |
|---|---|
| `openid` | Authentication — enables ID token issuance |
| `profile` | User's display name and avatar |
| `email` | User's email address and verification status |
| `offline_access` | Refresh token — allows silent re-authentication |

See [concepts/scopes.md](scopes.md) for the full table.

## Grant Types

sinauth supports two OAuth 2.0 grant types:

| Grant type | Description |
|---|---|
| `authorization_code` | The primary flow — user authenticates interactively and a code is exchanged for tokens. Always used with PKCE. |
| `refresh_token` | Silent token renewal — exchange a refresh token for a new access token without requiring the user to re-authenticate. |

Implicit grant, device code, and client credentials flows are not supported in v1.0.

## Tokens

OAuth 2.0 defines three token types:

| Token | Type | Lifetime | Purpose |
|---|---|---|---|
| Access token | RS256 JWT | 1 hour | Authorize API calls |
| ID token | RS256 JWT | 5 minutes | Identify the user (OIDC extension) |
| Refresh token | Opaque string | 30 days | Get a new access token silently |

See [concepts/tokens.md](tokens.md) for the full claim breakdown.
