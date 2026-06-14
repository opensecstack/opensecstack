---
status: Accepted
date: 2026-04-01
---
# ADR-002: HMAC-SHA256 for event authentication

## Context
Events arrive from multiple platforms over HTTP. CITADEL must verify that events are genuine and have not been tampered with in transit. Options: mTLS, asymmetric signatures (Ed25519), symmetric HMAC.

## Decision
Each emitting platform shares a symmetric HMAC-SHA256 secret with CITADEL (configured via `CITADEL_HMAC_SECRETS`, comma-separated for rotation). The emitter includes `X-Citadel-Signature: hex(HMAC-SHA256(secret, body))` and `X-Citadel-Key-ID` on every POST. CITADEL verifies against all active secrets (primary + rotation slots).

## Consequences
- Simple to implement in any language (Go, Python, Rust) — no PKI required
- Symmetric: if the shared secret leaks, an attacker can forge events — mitigated by secret rotation and short TTL
- Key-ID header allows zero-downtime rotation: new secret added, old secret removed after all emitters rotate
