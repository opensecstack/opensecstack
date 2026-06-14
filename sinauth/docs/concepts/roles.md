# Roles

## sinauth's position in RBAC

sinauth handles **authentication** (who are you?) and **coarse-grained authorization** (which scopes did you consent to?). It does not handle fine-grained, platform-specific roles — that is each platform's responsibility.

In v1.0, sinauth issues standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`). There are no custom per-platform role claims in the access token.

## How platforms map sinauth claims to their own RBAC

Each platform maintains its own roles table that maps a sinauth `sub` (user UUID) to platform-specific roles.

### Pattern: roles table

```sql
-- Example: APIGuard's user roles table
CREATE TABLE user_roles (
    user_id   UUID NOT NULL,  -- sinauth sub
    role      TEXT NOT NULL,  -- 'viewer', 'operator', 'admin'
    PRIMARY KEY (user_id, role)
);
```

When a user authenticates via sinauth, the platform:
1. Extracts `sub` from the verified access token (or ID token at login time).
2. Looks up the user's roles in its own `user_roles` table.
3. Enforces those roles for the duration of the session.

### First login provisioning

On a user's first login (when `sub` is not yet in the platform's `user_roles` table), the platform should assign a default role (typically `viewer` or `member`).

```go
// Go pseudo-code — on callback after token exchange
func handleCallback(sub, email, name string) {
    exists, _ := db.UserExists(sub)
    if !exists {
        // Provision the user with a default role
        db.CreateUser(sub, email, name, role: "member")
    }
    // Continue to platform dashboard
}
```

### Admin provisioning

Platform admins are provisioned by inserting rows directly into the `user_roles` table, or via the platform's admin UI. sinauth does not control which users are admins on which platforms — that is a platform-level concern.

## Planned: custom scopes (v2.0)

In v2.0, sinauth will support custom scopes such as `apiguard:scan:read` or `irflow:incident:write`. Platforms will be able to register their own scopes in sinauth and request them in the authorization flow. The granted scopes will appear in the access token, letting resource servers authorize requests without a database lookup.

This is an opt-in enhancement. The standard scopes will remain supported indefinitely.

## Using the `sub` claim as a stable user identifier

The `sub` claim (a UUID) is the only stable, globally-unique user identifier across all SIN platforms. Never use `email` as a primary key — email addresses can change. Always store `sub` as the foreign key reference to sinauth user accounts.

```go
// Correct: use sub as the foreign key
userID := tokenClaims["sub"].(string)  // UUID string

// Incorrect: do not use email as a primary key
email := tokenClaims["email"].(string)  // may change
```
