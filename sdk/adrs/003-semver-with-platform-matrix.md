---
status: Accepted
date: 2026-03-01
---
# ADR-003: SemVer with platform compatibility matrix

## Context
Platforms release independently. SDK consumers need to know which SDK version supports which platform API version.

## Decision
The SDK follows SemVer. Each release ships a `COMPATIBILITY.md` matrix mapping SDK version → supported platform API versions. Deprecated platform API versions are supported for one SDK major version after removal.

## Consequences
- Operators can pin SDK version and know exactly which platform APIs are supported
- Compatibility matrix must be updated on every SDK release (maintenance overhead)
- Breaking platform API changes force a SDK major bump
