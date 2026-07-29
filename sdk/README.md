# opensecstack SDK

> Go, Python, TypeScript, and Rust clients for inter-platform communication,
> plus a growing set of Go/TypeScript-only companion packages (`sinauth`
> identity, CITADEL MARSHAL governance signing, Argon2id password hashing).

The SDK provides typed contracts, event schemas, and client libraries that all opensecstack platforms use to communicate with each other and with CITADEL.

## What's Inside

| Component | Language(s) | Purpose |
|-----------|-------------|---------|
| Core client (APIGuard, NIS2 Compass, CITADEL WORM/AUGUR) | Go, Python, TypeScript, Rust | HTTP client for platform-to-platform and platform-to-CITADEL (event connector) communication |
| [`sinauth` client](go/sinauth/README.md) | Go, TypeScript | RS256 JWT verification and OIDC/PKCE helpers for the sinauth identity provider. No Python or Rust package yet |
| [`citadel` MARSHAL client](go/citadel/README.md) | Go only | Submits Kerkese governance requests to CITADEL's MARSHAL evaluation engine (`Evaluate`) and Ed25519-signs them as Operator/Verifier (`Sign`, `RegisterKey`). New — not yet ported to Python, TypeScript, or Rust, and not yet covered by a tagged SDK release (see [CHANGELOG.md](CHANGELOG.md)) |
| `password` hasher | Go, Python | Shared Argon2id (RFC 9106) + HMAC-SHA256 pepper password/API-key hashing; byte-compatible PHC encoding across the two languages. Published as separate packages ([`sdk/go/password`](go/password), `opensecstack-password` on PyPI). No TypeScript or Rust package yet |
| Event schemas | JSON Schema | Typed contracts for all inter-platform events |
| OpenAPI specs | YAML | API contracts for each platform's public endpoints |

## Language Matrix

This matrix covers the **core client** (APIGuard / NIS2 Compass / CITADEL event connector) shipped as the primary package per language. The `sinauth`, `citadel` MARSHAL, and `password` packages are separate modules — see the table above for their language coverage, which is narrower.

| Feature | Go | Python | TypeScript | Rust |
|---------|----|--------|------------|------|
| APIGuard client | Yes | Yes | Yes | Yes |
| NIS2 Compass client | Yes | Yes | Yes | Yes |
| CITADEL event/WORM client (`SendEvent`/`GetEvents`/`VerifyChain`) | Yes | Yes | Yes | Yes |
| CITADEL MARSHAL client (Kerkese `Evaluate` + Ed25519 `Sign`) | Yes (`sdk/go/citadel`, new) | — | — | — |
| sinauth OIDC/JWT client | Yes (`sdk/go/sinauth`) | — | Yes (`@opensecstack/sinauth`) | — |
| Password hashing (Argon2id + pepper) | Yes (`sdk/go/password`) | Yes (`opensecstack-password`) | — | — |
| AUGUR advisory client | Yes | Yes | Yes | — |
| Webhook router | Yes | Yes | Yes | — |
| Async / non-blocking | Yes (goroutines) | Yes (asyncio) | Yes (async/await) | Yes (tokio) |
| Auto token refresh | Yes | Yes | Yes | Yes |
| Redirect guard (SDK-M4) | Yes | Yes | Yes | Yes |
| JWT exp parsing (SDK-M5) | Yes | Yes | Yes | Yes |
| Report streaming | Yes | Yes | Yes | Yes |
| Client builder pattern | — | — | — | Yes (`APIGuardClientBuilder`, `NIS2CompassClientBuilder`) |
| Min runtime version | Go 1.24 (core client); `sinauth`/`citadel` sub-modules target Go 1.22 | Python 3.11 | Node.js 18 | Rust 1.75 |

> Note on "Builder pattern": only the Rust client currently exposes an
> explicit builder type. The Go and Python packages do not — the prior
> version of this table listed them as "Yes" in error (the only matches in
> those codebases were unrelated uses of `strings.Builder`).

## Integration Contracts

| Contract | Format | Version | Description |
|----------|--------|---------|-------------|
| Scan Result | JSON | v1 | APIGuard → IRFlow, ThreatFlow, NIS2 Compass |
| IOC Bundle | STIX 2.1 | v1 | ThreatFlow → OpenScrub, IRFlow, OpenCSIRT |
| Incident Record | JSON | v1 | IRFlow → NIS2 Compass, OpenCSIRT, CITADEL |
| Compliance Evidence | JSON | v1 | NIS2 Compass → CITADEL |
| CITADEL Event | JSON | v2.0 | Any platform → CITADEL (MARSHAL input) |
| Training Record | JSON | v1 | CyberPath → NIS2 Compass, CITADEL |
| Advisory | CSAF 2.0 | v1 | OpenCSIRT → ThreatFlow |
| Simulation Result | JSON | v1 | SecureLab → IRFlow, OpenScrub, ThreatFlow |

## Documentation

| Document | Description |
|----------|-------------|
| [Go Client](docs/go-client.md) | Typed Go clients for APIGuard, NIS2 Compass, and the CITADEL event connector, plus shared contract types |
| [Python Client](docs/python-client.md) | Typed Python clients for APIGuard and NIS2 Compass, plus contract dataclasses |
| [TypeScript Client](docs/typescript-client.md) | Typed TypeScript clients for APIGuard, NIS2 Compass, and the CITADEL event connector, plus webhook router with HMAC-SHA256 verification |
| [Rust Client](docs/rust-client.md) | Async, type-safe Rust clients for APIGuard and NIS2 Compass built on tokio + reqwest |
| [sinauth Go Client](go/sinauth/README.md) | RS256 JWT verification, HTTP middleware, and UserInfo lookups for the sinauth identity provider |
| [sinauth TypeScript Client](typescript/sinauth/README.md) | `@opensecstack/sinauth` — RS256 JWT verification and OAuth2 PKCE helpers |
| [CITADEL MARSHAL Go Client](go/citadel/README.md) | `sdk/go/citadel` — Kerkese governance requests, MARSHAL evaluation, and Ed25519 Operator/Verifier signing |
| [Contracts](docs/contracts.md) | Typed integration contracts for data exchanged between opensecstack platforms |
| [Events](docs/events.md) | Typed event system for webhooks and async notifications, including signature verification and event routing |
| [Migration Guide](docs/migration.md) | Breaking changes and upgrade instructions for each SDK release |
| [Troubleshooting](docs/troubleshooting.md) | Common integration issues with symptoms, root causes, and copy-paste solutions |

## Status

**Core SDK: v1.0.0 — Production.** API surface frozen for the four core language clients (Go, Python, TypeScript, Rust — APIGuard, NIS2 Compass, CITADEL event/WORM connector). These are stable and covered by semantic versioning guarantees; see [CHANGELOG.md](CHANGELOG.md).

**Newer, narrower-scope packages are not yet covered by that guarantee:**

- `sdk/go/password` and `opensecstack-password` (Python) — added post-1.0.0 (see CHANGELOG `[Unreleased]`), each with a full test suite, but not yet part of a tagged SDK release.
- `sdk/go/sinauth` and `@opensecstack/sinauth` (TypeScript) — sinauth identity clients. Not yet listed in CHANGELOG.md; verify current test coverage before treating either as production-frozen.
- `sdk/go/citadel` — the CITADEL MARSHAL Kerkese client, built most recently of all of these. Has a unit test suite (`client_test.go`, `sign_test.go`) covering `Evaluate`'s EXECUTE/REFUSE/HARD_STOP paths and `Sign`'s canonical-payload determinism, but is Go-only, unreleased, and not yet mentioned in CHANGELOG.md.

## Licence

Apache 2.0
