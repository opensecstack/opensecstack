---
status: Accepted
date: 2026-05-01
---
# ADR-003: Ed25519 fingerprint for peer CSIRT identity

## Context
OpenCSIRT federates with peer CSIRTs (FIRST, TF-CSIRT, CSIRTs Network). Peer identity must be verifiable without a central PKI.

## Decision
Each peer CSIRT record stores an `ed25519_fingerprint` (hex-encoded SHA-256 of the peer's Ed25519 public key). Handshakes are recorded with a timestamp. Trust levels (verified / pending / failed / expired) are managed manually by `csirt_lead+` operators pending automated key exchange in v0.2.

## Consequences
- No dependency on X.509 or a CA — self-sovereign identity
- Trust is manually curated in v0.1 (acceptable for a small peer network)
- Fingerprint rotation requires a new handshake and manual re-verification
