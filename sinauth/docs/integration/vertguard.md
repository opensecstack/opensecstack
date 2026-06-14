# Integrating VertGuard with sinauth

**Platform**: VertGuard
**Purpose**: Vendor and third-party security risk assessment — evaluate the security posture of vendors, suppliers, and partners against configurable security frameworks.
**URL**: `vertguard.sin.to`

## Client registration (stub)

```json
{
  "client_id": "vertguard",
  "name": "VertGuard",
  "redirect_uris": [
    "https://vertguard.sin.to/auth/callback",
    "http://localhost:5183/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the risk assessor |
| `profile` | Attribute vendor assessments and findings to named assessors |
| `email` | Notify assessors of vendor questionnaire responses and assessment deadlines |
| `offline_access` | Maintain session during multi-session vendor assessment workflows |

## Redirect URI example

```
https://vertguard.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
