# CITADEL Roadmap

Direction for CITADEL after the v1.0.0 release. Items shift with
ecosystem needs — open an issue with label `roadmap` to propose
changes.

## Completed (v1.0.0)

- MARSHAL 5-gate decision engine (AuthN → AuthZ → NDS → AUGUR → WORM)
- WORM hash chain with SHA-256 chain linking and per-entry TripleHash
- Ed25519 chain anchors signed at configurable intervals
- NDS protocol (Separation of Duties) enforced at Gate 3
- REST API: `/marshal/evaluate`, `/worm/emit`, `/worm/verify`, `/health`
- PostgreSQL 16 persistence with versioned migrations
- Structured JSON logging (zerolog), graceful shutdown, security headers
- Benchmark baselines: TripleHash 1.52 µs, WORM append 4.22 ms, MARSHAL
  evaluation 7.55 µs (in-memory mock)
- Docker image with non-root user + build-arg version injection

## v1.1 — Hardening (6-8 weeks post-v1.0.0)

| Item | Description |
|---|---|
| Overlapping-secret rotation | Accept the previous HMAC secret for a grace window when rotating, rather than requiring a maintenance cut-over |
| Anchor batch-sign | Coalesce pending anchors into a single Ed25519 signature per batch to cut per-write crypto cost |
| Chain verification streaming | `GET /worm/verify` currently buffers; streaming incremental verification removes the chain-length memory cap |
| Prometheus metrics | `/metrics` catalogue — MARSHAL gate outcomes, WORM lag, anchor-interval histograms |
| Integration tests against real CITADEL | Existing tests use in-memory mocks; promote a subset to hit a live Postgres |
| OpenAPI 3 spec | Machine-readable wire contract for SDK code-generation downstream |

## v1.2 — ERP layer (after v1.1)

A dedicated governance ERP (Odoo-inspired but Go/Python-native — **not**
based on the Odoo framework) lands as a separate module under `citadel/erp/`.
This brings case-management UI for audit workflows that operators
currently drive through raw API calls.

| Item | Description |
|---|---|
| ERP connector layer | `citadel/erp/connectors/` — adapters for external ticketing (GitHub, GitLab, Jira) and ERP (SAP, Dynamics) for evidence export |
| Case management UI | Browser UI for reviewing pending MARSHAL REFUSE cases and submitting appeals |
| Evidence chain viewer | Web dashboard for auditors with time-range filtering and export to STIX 2.1 |
| Multi-ERP federation | Schema for replicating evidence across peer CITADEL instances with signed proof-of-presence |

## v2.0 — Multi-writer chain (exploratory)

Today CITADEL is single-writer — the WORM chain tolerates only one
primary at a time, with active/passive failover via a leader lock
(Consul, Kubernetes Lease). For sharded or regionalised deployments:

| Item | Description |
|---|---|
| Sharded chains by `project_id` | Each project gets its own chain; cross-project queries aggregate proofs |
| Multi-writer consensus | Paxos- or Raft-backed anchor agreement to accept writes from N replicas |
| VIGIL implementation | The documented GREEN/AMBER/RED health monitor becomes real code (today it is design-stage only) |
| HSM anchor keys | Move the Ed25519 anchor key into a TPM/HSM/Cloud-KMS slot with a PKCS#11 or KMIP adapter |

## Non-goals

- **No full ERP rewrite.** The ERP layer wraps CITADEL — it does not
  replace the Go governance core.
- **No mutable WORM.** "Redaction" is achieved via compensating entries,
  never by deleting or altering an existing chain entry.
- **No built-in identity provider.** JWT verification is all CITADEL
  does; token issuance belongs elsewhere.
- **No MARSHAL gates beyond 5.** If a new check is needed, it extends
  an existing gate; adding gate 6 changes the evaluation semantics in
  ways downstream platforms cannot safely absorb.

## Call for feedback

Planning reviews are informal today. File a GitHub issue with the
`roadmap` label to propose additions, or open an RFC under
[../rfcs/](../rfcs/) for anything that changes the evaluation
semantics or chain layout.
