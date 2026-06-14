---
status: Accepted
date: 2026-05-01
---
# ADR-001: CSAF 2.0 as advisory format

## Context
OpenCSIRT must publish machine-readable security advisories. Formats considered: CSAF 2.0, CVRF 1.2 (deprecated), custom JSON.

## Decision
CSAF 2.0 (Common Security Advisory Framework, OASIS standard) is the mandatory format for all advisories. A Python subsystem (`advisory` service) generates and validates CSAF documents. The Go API stores the raw CSAF JSON and exposes it via `GET /api/v1/advisories/{id}/csaf`.

## Consequences
- Interoperable with BSI, CERT/CC, and ENISA tooling out of the box
- Python subsystem adds an operational dependency (Go API falls back to NoopClient if unreachable)
- CSAF 2.0 schema validation catches malformed advisories before publish
