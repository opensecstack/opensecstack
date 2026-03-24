# opensecstack SDK

> Go + Python clients for inter-platform communication.

The SDK provides typed contracts, event schemas, and client libraries that all opensecstack platforms use to communicate with each other and with CITADEL.

## What's Inside

| Component | Language | Purpose |
|-----------|----------|---------|
| Go client | Go | HTTP client for platform-to-platform and platform-to-CITADEL communication |
| Python client | Python | Same capabilities for Python-based platforms (NIS2 Compass, SecureLab) |
| Event schemas | JSON Schema | Typed contracts for all inter-platform events |
| OpenAPI specs | YAML | API contracts for each platform's public endpoints |

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

## Status

In development. Initial contracts being defined alongside APIGuard v0.1.0.

## Licence

Apache 2.0
