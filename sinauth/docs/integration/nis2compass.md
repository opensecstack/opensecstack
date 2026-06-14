# Integrating NIS2Compass with sinauth

**Platform**: NIS2Compass
**Purpose**: NIS2 directive compliance tracking and gap assessment for organizations operating under EU cybersecurity regulation.
**URL**: `nis2compass.sin.to`

## Client registration (stub)

```json
{
  "client_id": "nis2compass",
  "name": "NIS2Compass",
  "redirect_uris": [
    "https://nis2compass.sin.to/auth/callback",
    "http://localhost:5177/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the compliance analyst |
| `profile` | Display analyst name in compliance reports and audit trails |
| `email` | Notify analysts of compliance deadline changes and assessment reminders |
| `offline_access` | Maintain session during extended compliance reviews |

## Redirect URI example

```
https://nis2compass.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
