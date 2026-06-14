# Integrating ThreatFlow with sinauth

**Platform**: ThreatFlow
**Purpose**: Threat intelligence aggregation, indicator of compromise (IoC) management, and threat sharing across the SIN ecosystem.
**URL**: `threatflow.sin.to`

## Client registration (stub)

```json
{
  "client_id": "threatflow",
  "name": "ThreatFlow",
  "redirect_uris": [
    "https://threatflow.sin.to/auth/callback",
    "http://localhost:5178/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the analyst |
| `profile` | Attribute IoC submissions and threat reports to named analysts |
| `email` | Alert analysts on new high-severity threat indicators |
| `offline_access` | Keep analysts logged in during active threat monitoring sessions |

## Redirect URI example

```
https://threatflow.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
