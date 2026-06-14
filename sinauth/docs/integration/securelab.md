# Integrating SecureLab with sinauth

**Platform**: SecureLab
**Purpose**: Hands-on security lab environment — browser-accessible virtual machines and challenges for practical security training and CTF-style exercises.
**URL**: `securelab.sin.to`

## Client registration (stub)

```json
{
  "client_id": "securelab",
  "name": "SecureLab",
  "redirect_uris": [
    "https://securelab.sin.to/auth/callback",
    "http://localhost:5181/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the lab user |
| `profile` | Display participant name in challenge leaderboards and lab history |
| `email` | Notify users of lab environment expiry and challenge updates |
| `offline_access` | Keep users logged in during long-running lab sessions (labs can run for hours) |

## Redirect URI example

```
https://securelab.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
