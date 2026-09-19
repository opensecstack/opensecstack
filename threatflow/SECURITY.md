# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in ThreatFlow, **do not open a public issue**.

Instead, report it via one of:

- Email: **security@opensecstack.org**
- GitHub Security Advisory: [Report a vulnerability](https://github.com/opensecstack/opensecstack/security/advisories/new)

We will acknowledge receipt within 48 hours and provide a timeline for a fix within 7 days.

## Scope

This policy covers:

- The ThreatFlow HTTP API and all endpoints
- IOC ingestion and STIX 2.1 parsing
- CITADEL HMAC-SHA256 connector authentication
- Feed polling and credential handling
- No ThreatFlow images have been published to a registry yet; build
  locally with `docker build` (see README) until a release is published

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |

## Disclosure Policy

- We follow coordinated disclosure with a 90-day window
- CVEs are requested for confirmed vulnerabilities
- Security fixes are released as patch versions
- All security events are WORM-logged in CITADEL

See also: [Security Model](docs/security-model.md)
