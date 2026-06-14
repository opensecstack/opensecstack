---
status: Accepted
date: 2026-04-01
---
# ADR-001: STIX 2.1 as canonical IOC format

## Context
ThreatFlow ingests IOCs from multiple sources (IRFlow webhooks, VertGuard alerts, peer CSIRTs, manual upload). A canonical internal format is needed for deduplication, enrichment, and sharing.

## Decision
All IOCs are normalised to STIX 2.1 objects (Indicator, Malware, ThreatActor, Relationship) on ingest. Raw source data is preserved in `extensions`. Sharing to downstream platforms (OpenCSIRT, APIGuard) uses STIX 2.1 bundles over TAXII 2.1.

## Consequences
- Industry-standard format — downstream consumers need no ThreatFlow-specific parsing
- STIX 2.1 is verbose; storage is larger than a flat IOC table
- Relationship modelling (actor → malware → indicator) enables richer graph queries
