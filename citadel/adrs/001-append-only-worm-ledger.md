---
status: Accepted
date: 2026-04-01
---
# ADR-001: Append-only WORM ledger design

## Context
CITADEL must provide tamper evidence for security-critical events across all opensecstack platforms. If CITADEL records could be updated or deleted, the audit trail would be meaningless.

## Decision
The events table has no UPDATE or DELETE paths at the application layer. The API exposes only POST (emit) and GET (query). PostgreSQL row-level security enforces INSERT-only for the application role. Periodic Merkle-tree snapshots anchor the chain — any gap or reordering is detectable.

## Consequences
- Storage grows indefinitely; archival to object storage (S3/MinIO) is required for long-running deployments
- Correcting a mistaken event requires a compensating event, not a deletion (append-only correction pattern)
- Compliance: satisfies NIS2 Article 21 logging requirements for "appropriate technical measures"
