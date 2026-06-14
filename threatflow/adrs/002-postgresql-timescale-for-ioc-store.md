---
status: Accepted
date: 2026-04-01
---
# ADR-002: PostgreSQL with time-partitioned IOC table

## Context
IOCs are time-series in nature — ingestion timestamp and expiry are first-class query dimensions. Options: TimescaleDB, plain PostgreSQL range partitioning, or a dedicated time-series DB.

## Decision
Use plain PostgreSQL 16 with declarative range partitioning on `ingested_at` (monthly partitions). No TimescaleDB extension dependency. Partition pruning covers the dominant query pattern (last 30/90 days).

## Consequences
- No additional extension to install or license
- Partition maintenance (creation, detach, drop) must be automated via a cron job
- Suitable for <500M IOCs/year; beyond that, TimescaleDB or ClickHouse should be re-evaluated
