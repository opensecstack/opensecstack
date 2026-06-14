# Integrating OpenScrub with sinauth

**Platform**: OpenScrub
**Purpose**: Data discovery and sensitive data scrubbing tool — scans codebases, databases, and file stores for exposed secrets, PII, and sensitive data patterns.
**URL**: `openscrub.sin.to`

## Client registration (stub)

```json
{
  "client_id": "openscrub",
  "name": "OpenScrub",
  "redirect_uris": [
    "https://openscrub.sin.to/auth/callback",
    "http://localhost:5182/auth/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "require_pkce": true,
  "is_confidential": false
}
```

## Required scopes

| Scope | Why |
|---|---|
| `openid` | Required — identifies the security engineer |
| `profile` | Attribute scan results and findings reports to named engineers |
| `email` | Alert engineers when critical findings (exposed secrets) are detected |
| `offline_access` | Maintain session during long-running data discovery scans |

## Redirect URI example

```
https://openscrub.sin.to/auth/callback
```

---

Full integration guide coming soon. For now, follow the [generic integration guide](custom.md) using the client configuration above.
