# Integrating CyberPath with sinauth

**Platform**: CyberPath
**Purpose**: Cybersecurity learning paths and skill development — structured curriculum for security practitioners at all levels.
**URL**: `cyberpath.sin.to`

## Client registration (stub)

```json
{
  "client_id": "cyberpath",
  "name": "CyberPath",
  "redirect_uris": [
    "https://cyberpath.sin.to/auth/callback",
    "http://localhost:5180/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the learner |
| `profile` | Display learner name and avatar on leaderboards and certificates |
| `email` | Send course completion certificates and learning reminders |
| `offline_access` | Persist learning progress sessions without requiring re-login |

## Redirect URI example

```
https://cyberpath.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
