# Integrating APIGuard with sinauth

APIGuard is the API security testing platform in the SIN ecosystem (`apiguard.sin.to`). It allows operators to run security scans against API endpoints and view findings.

## Client registration

```json
{
  "client_id": "apiguard",
  "name": "APIGuard",
  "redirect_uris": [
    "https://apiguard.sin.to/auth/callback",
    "http://localhost:5175/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false,
  "logo_url": "https://apiguard.sin.to/logo.svg"
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the user |
| `profile` | Display operator name in scan history and reports |
| `email` | Notify operators of completed scans and critical findings |
| `offline_access` | Keep operators logged in during long-running scan sessions |

## Claim mapping

| sinauth claim | APIGuard field | Notes |
|---|---|---|
| `sub` | `users.sinauth_id` | Primary foreign key |
| `email` | `users.email` | Used for scan result notifications |
| `name` | `users.display_name` | Shown in scan history and audit trails |
| `email_verified` | — | Not gated in APIGuard — email is for notifications only |

## Operator roles

sinauth does not define APIGuard-specific roles. APIGuard maintains its own role model:

| Role | Capabilities |
|---|---|
| `viewer` | View scans and findings |
| `operator` | Run scans, view findings, export reports |
| `admin` | All above + manage targets, manage users, configure scan policies |

Default role for new users: `viewer`. Admins promote users to `operator` or `admin` via the APIGuard admin panel.

First-login provisioning pattern:

```go
claims, _ := verifyIDToken(tokens.IDToken)

user, _ := db.UpsertUser(apiguard.User{
    SinauthID:   claims.Sub,
    Email:       claims.Email,
    DisplayName: claims.Name,
    Role:        "viewer",  // default role
})
```

## Scan-specific authorization

For scan execution, APIGuard's internal API checks the user's local role — sinauth claims alone are not sufficient. The access token's `sub` claim is used as the lookup key:

```go
// On every scan request
userID := extractSub(accessToken)      // verify RS256, extract sub
user, err := db.GetUserBySinauthID(userID)
if user.Role != "operator" && user.Role != "admin" {
    return ErrForbidden
}
// proceed with scan
```

## Custom scopes (planned v2.0)

In v2.0, sinauth will support custom scopes. APIGuard plans to request:

- `apiguard:scan:read` — view scans and findings
- `apiguard:scan:write` — create and run scans
- `apiguard:admin` — manage targets and users

These will be encoded directly in the access token, eliminating the per-request role lookup.

## See also

- [Generic integration guide](custom.md) — full PKCE flow code examples
- [Concepts: Roles](../concepts/roles.md) — how sinauth claims map to platform RBAC
