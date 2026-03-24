# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in any opensecstack platform, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities** — this exposes users before a fix is available.

| Channel | Address | Use For |
|---------|---------|---------|
| GitHub Security Advisory | Per-platform: `github.com/opensecstack/<platform>/security/advisories/new` | Preferred method. Private. GitHub handles coordination. |
| Email | security@opensecstack.org | Alternative if GitHub advisory not accessible. |
| PGP Encrypted Email | Key: keybase.io/opensecstack | For sensitive vulnerabilities requiring encryption. |

## Response SLA

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours of report |
| Initial assessment | Within 7 days |
| Fix for CRITICAL | Within 14 days of confirmation |
| Fix for HIGH | Within 30 days of confirmation |
| Fix for MEDIUM/LOW | Within 90 days of confirmation |
| Public disclosure | After fix is released and users have had 30 days to update |
| CVE assignment | Requested for all confirmed vulnerabilities |

## Scope

**IN SCOPE:**
- All opensecstack platform code (APIGuard, NIS2 Compass, ThreatFlow, IRFlow, OpenScrub, CyberPath, SecureLab, OpenCSIRT)
- CITADEL governance layer
- opensecstack/sdk
- Docker images published to ghcr.io/opensecstack/*
- opensecstack.org website and infrastructure

**OUT OF SCOPE:**
- Target systems being scanned/tested by opensecstack tools (those are your systems)
- Intentionally vulnerable test targets (VAmPI, crAPI, etc.)
- Third-party dependencies (report to the upstream project, but let us know)

## Security Design Principles

opensecstack is built on these security principles:

1. **Untrusted input is parsed in memory-safe languages** (Rust) wherever possible
2. **Secrets never appear in logs** — all logging redacts sensitive material
3. **CITADEL audit trail is append-only** — no record can be modified after creation
4. **Separation of duties** is enforced by CITADEL, not by convention
5. **Every platform publishes an SBOM** with each release
