---
status: Accepted
date: 2026-03-01
---
# ADR-002: One typed client struct per platform

## Context
The SDK must cover 10+ platforms. A single generic HTTP client would lose type safety; a monolithic client would be hard to maintain.

## Decision
Each platform gets its own client struct (e.g. `apiguard.Client`, `opencsirt.Client`, `threatflow.Client`) with methods matching the platform's OpenAPI spec. A shared `transport.Client` handles JWT refresh, retry, and TLS.

## Consequences
- Callers import only the platform client they need — no bloat
- Adding a new platform requires only a new sub-package
- Breaking API changes surface as compile errors in SDK consumers
