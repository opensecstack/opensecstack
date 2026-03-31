# opensecstack SDK

> Go, Python, TypeScript, and Rust clients for inter-platform communication.

The SDK provides typed contracts, event schemas, and client libraries that all opensecstack platforms use to communicate with each other and with CITADEL.

## What's Inside

| Component | Language | Purpose |
|-----------|----------|---------|
| Go client | Go | HTTP client for platform-to-platform and platform-to-CITADEL communication |
| Python client | Python | Same capabilities for Python-based platforms (NIS2 Compass, SecureLab) |
| TypeScript client | TypeScript | Browser and Node.js client using native `fetch` API |
| Rust client | Rust | Async-first client for high-performance and systems integration use-cases |
| Event schemas | JSON Schema | Typed contracts for all inter-platform events |
| OpenAPI specs | YAML | API contracts for each platform's public endpoints |

## Language Matrix

| Feature | Go | Python | TypeScript | Rust |
|---------|----|--------|------------|------|
| APIGuard client | Yes | Yes | Yes | Yes |
| NIS2 Compass client | Yes | Yes | Yes | Yes |
| CITADEL client | Yes | Yes | Yes | Yes |
| AUGUR advisory client | Yes | Yes | Yes | — |
| Webhook router | Yes | Yes | Yes | — |
| Async / non-blocking | Yes (goroutines) | Yes (asyncio) | Yes (async/await) | Yes (tokio) |
| Auto token refresh | Yes | Yes | Yes | Yes |
| Redirect guard (SDK-M4) | Yes | Yes | Yes | Yes |
| JWT exp parsing (SDK-M5) | Yes | Yes | Yes | Yes |
| Report streaming | Yes | Yes | Yes | Yes |
| Builder pattern | Yes | Yes | — | Yes |
| Min runtime version | Go 1.24 | Python 3.11 | Node.js 18 | Rust 1.75 |

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
| [Go Client](docs/go-client.md) | Typed Go clients for APIGuard, NIS2 Compass, and CITADEL, plus shared contract types |
| [Python Client](docs/python-client.md) | Typed Python clients for APIGuard and NIS2 Compass, plus contract dataclasses |
| [TypeScript Client](docs/typescript-client.md) | Typed TypeScript clients for APIGuard, NIS2 Compass, and CITADEL, plus webhook router with HMAC-SHA256 verification |
| [Rust Client](docs/rust-client.md) | Async, type-safe Rust clients for APIGuard and NIS2 Compass built on tokio + reqwest |
| [Contracts](docs/contracts.md) | Typed integration contracts for data exchanged between opensecstack platforms |
| [Events](docs/events.md) | Typed event system for webhooks and async notifications, including signature verification and event routing |
| [Migration Guide](docs/migration.md) | Breaking changes and upgrade instructions for each SDK release |
| [Troubleshooting](docs/troubleshooting.md) | Common integration issues with symptoms, root causes, and copy-paste solutions |

## Status

In development. Initial contracts being defined alongside APIGuard v0.1.0.

## Licence

Apache 2.0
