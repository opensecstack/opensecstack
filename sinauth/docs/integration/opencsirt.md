# Integrating OpenCSIRT with sinauth

**Platform**: OpenCSIRT
**Purpose**: Computer Security Incident Response Team (CSIRT) coordination platform — manages vulnerability disclosures, inter-team communication, and coordinated response workflows.
**URL**: `opencsirt.sin.to`

## Client registration (stub)

```json
{
  "client_id": "opencsirt",
  "name": "OpenCSIRT",
  "redirect_uris": [
    "https://opencsirt.sin.to/auth/callback",
    "http://localhost:5179/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the CSIRT member |
| `profile` | Display member identity in disclosure coordination threads |
| `email` | Coordinate disclosure timelines and notifications via email |
| `offline_access` | Maintain session during multi-day coordinated disclosure processes |

## Redirect URI example

```
https://opencsirt.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
