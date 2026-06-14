---
status: Accepted
date: 2026-03-01
---
# ADR-001: Go as primary SDK language

## Context
The opensecstack platform APIs (APIGuard, OpenCSIRT, ThreatFlow, IRFlow, etc.) are all written in Go. Operators need a typed client library that matches the API contracts exactly.

## Decision
Go is the primary SDK language. A TypeScript SDK is provided as a secondary target for web frontend consumers.

## Consequences
- Single source of truth for types (Go structs → generated TS interfaces)
- No runtime type mismatches between SDK and platform handlers
- Operators without Go experience must use the REST API or TypeScript SDK directly
