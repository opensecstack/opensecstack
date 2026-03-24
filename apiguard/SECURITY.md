# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in APIGuard, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

| Channel | Address | Use For |
|---------|---------|---------|
| GitHub Security Advisory | [Create Advisory](https://github.com/opensecstack/apiguard/security/advisories/new) | Preferred method. Private. |
| Email | security@opensecstack.org | Alternative if GitHub advisory not accessible. |
| PGP Encrypted Email | Key: keybase.io/opensecstack | For sensitive vulnerabilities requiring encryption. |

## Response SLA

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix for CRITICAL | Within 14 days of confirmation |
| Fix for HIGH | Within 30 days of confirmation |
| Fix for MEDIUM/LOW | Within 90 days of confirmation |
| Public disclosure | After fix released + 30 days for users to update |
| CVE assignment | Requested for all confirmed vulnerabilities |

## Scope

**IN SCOPE:**
- APIGuard core (parser, scanner, reporter, dashboard, API server)
- opensecstack/sdk when used by APIGuard
- Docker images published to ghcr.io/opensecstack/apiguard

**OUT OF SCOPE:**
- Target APIs being scanned by APIGuard (those are your systems)
- Vulnerabilities in test targets (VAmPI, crAPI) — those are intentionally vulnerable
