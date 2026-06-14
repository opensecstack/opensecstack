# SSO Sessions

## What is an SSO session?

When a user logs in to sinauth (via the login form, Google, or GitHub), sinauth creates an **SSO session** and sets a `sinauth_session` cookie in the user's browser.

This session is the basis for single sign-on across all SIN platforms: as long as the session cookie is valid, the user does not need to type their password again when navigating to a different SIN platform. sinauth recognizes the existing session, skips the login form, and immediately redirects back with an authorization code.

One login → access to all 10 SIN platforms for the lifetime of the session.

## Session storage

Sessions are stored in the `sso_sessions` table in PostgreSQL:

```sql
CREATE TABLE sso_sessions (
    id         TEXT PRIMARY KEY,      -- random session ID (cookie value)
    user_id    UUID NOT NULL,         -- references users(id)
    username   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
```

The cookie value is an opaque random string (UUID v4). It maps to a row in `sso_sessions`.

## Session cookie

The `sinauth_session` cookie is set with:

| Attribute | Value | Reason |
|---|---|---|
| `HttpOnly` | true | JavaScript cannot read the cookie, preventing XSS-based session theft |
| `Secure` | true (in production) | Cookie is only sent over HTTPS |
| `SameSite` | `Lax` | Prevents CSRF for most cross-site requests while allowing top-level navigation |
| `Path` | `/` | Cookie is sent for all sinauth paths |

The cookie's `Max-Age` matches the session TTL configured in sinauth.

## Session TTL

SSO sessions are long-lived by default (aligned with the refresh token TTL of 30 days). The session expires either at the configured TTL or when the user explicitly logs out.

A new session is created at each login. Expired sessions are garbage-collected via a background job that removes rows where `expires_at < now()`.

## SSO flow with an existing session

When a platform redirects the user to `GET /oauth/authorize`:

1. sinauth checks for the `sinauth_session` cookie.
2. If the cookie is present, sinauth looks up the session in the database.
3. If the session is valid (not expired), sinauth skips the login form entirely.
4. If consent was previously granted, sinauth skips the consent screen.
5. sinauth generates an authorization code and immediately redirects back to the platform.

The entire flow is transparent to the user — they see no login UI.

## Logout: `/oauth/endsession`

Calling `GET /oauth/endsession` ends the SSO session:

1. sinauth reads the `sinauth_session` cookie.
2. sinauth deletes the session row from `sso_sessions`.
3. sinauth clears the `sinauth_session` cookie (sets `Max-Age=0`).
4. sinauth redirects to `post_logout_redirect_uri` (if provided and allowed) or the sinauth login page.

After logout, the next visit to any SIN platform requires the user to authenticate again.

### Front-channel logout

In v1.0, logout is single-service: the user must be redirected to sinauth's `/oauth/endsession` endpoint. Each platform should link to this endpoint with a `post_logout_redirect_uri` pointing back to their own logout page.

Multi-platform front-channel logout (where logging out of one platform logs you out of all platforms simultaneously) is planned for v2.0.

## Session security

- Session IDs are cryptographically random UUIDs — not predictable.
- Sessions are validated server-side on every authorization request — a stolen cookie becomes useless after the session is deleted.
- `HttpOnly` + `Secure` + `SameSite=Lax` provides defense-in-depth against the most common cookie attacks.
