# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | Yes |

## Reporting a Vulnerability

Email: security@sin.to
Response time: 48 hours
Disclosure: coordinated after patch

## Security Model

- Private keys never leave the server
- All tokens signed RS256
- PKCE required for all clients
- Bcrypt cost 12 for passwords
- Audit log for all auth events
