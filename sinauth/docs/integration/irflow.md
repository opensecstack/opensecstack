# Integrating IRFlow with sinauth

IRFlow is the incident response platform in the SIN ecosystem (`irflow.sin.to`). It provides structured workflows for tracking, managing, and resolving security incidents.

## Client registration

```json
{
  "client_id": "irflow",
  "name": "IRFlow",
  "redirect_uris": [
    "https://irflow.sin.to/auth/callback",
    "http://localhost:5176/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false,
  "logo_url": "https://irflow.sin.to/logo.svg"
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the responder |
| `profile` | Display responder name in incident timeline and activity log |
| `email` | Notify responders of incident assignments and escalations |
| `offline_access` | Maintain session during active incident response (may last hours) |

## Claim mapping

| sinauth claim | IRFlow field | Notes |
|---|---|---|
| `sub` | `users.sinauth_id` | Primary foreign key — stable across sessions |
| `email` | `users.email` | Used for incident notifications and escalation emails |
| `name` | `users.display_name` | Shown in incident timeline, comments, and status updates |

## Incident operator roles

IRFlow maintains its own role model for incident operations:

| Role | Capabilities |
|---|---|
| `observer` | View incidents and timelines (read-only) |
| `responder` | Assigned to incidents, update status, add timeline entries |
| `lead` | All responder capabilities + assign responders, escalate, close incidents |
| `admin` | All above + configure playbooks, manage users, view analytics |

Default role for new users: `observer`. Admins promote users to `responder` or higher via the IRFlow admin panel.

## Incident assignment and `sub` usage

Every incident action (status update, comment, timeline entry) records the `sub` of the acting user:

```go
type TimelineEntry struct {
    IncidentID  string
    ActorID     string    // sinauth sub
    Action      string
    Description string
    CreatedAt   time.Time
}

// On each action
actorSub := extractSub(accessToken)
irflow.AppendTimeline(TimelineEntry{
    IncidentID:  incidentID,
    ActorID:     actorSub,
    Action:      "status_updated",
    Description: "Status changed to Contained",
})
```

This creates an immutable, auditable record of who did what and when, traceable back to the sinauth user account.

## Session handling for long-running incidents

Incident response sessions can span hours. IRFlow proactively refreshes the access token before it expires using the refresh token:

```go
// Check token expiry before each significant operation
if time.Until(accessTokenExpiry) < 5*time.Minute {
    newTokens, err := refreshAccessToken(refreshToken)
    // update stored tokens
}
```

The `offline_access` scope is required to receive a refresh token. Operators without this scope will be logged out after 1 hour.

## Custom scopes (planned v2.0)

In v2.0, IRFlow plans to request:

- `irflow:incident:read` — view incidents
- `irflow:incident:write` — update incidents and timelines
- `irflow:incident:lead` — lead and close incidents
- `irflow:admin` — manage playbooks and users

## See also

- [Generic integration guide](custom.md) — full PKCE flow code examples
- [Concepts: Sessions](../concepts/sessions.md) — SSO session behavior
- [Concepts: Tokens](../concepts/tokens.md) — refresh token details
