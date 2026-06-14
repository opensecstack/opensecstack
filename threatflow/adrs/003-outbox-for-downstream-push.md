---
status: Accepted
date: 2026-04-01
---
# ADR-003: Transactional outbox for downstream IOC push

## Context
When a new IOC is ingested, it must be pushed to OpenCSIRT (advisory enrichment), APIGuard (block-list update), and CITADEL (evidence). A direct HTTP call inside the ingest transaction risks partial failure — IOC stored but push lost.

## Decision
Use the transactional outbox pattern: the ingest handler writes the IOC and an outbox event in the same DB transaction. A background sweeper reads undelivered outbox events and pushes them, marking each delivered or dead-lettered after 3 retries.

## Consequences
- At-least-once delivery guaranteed even if the push target is temporarily down
- Outbox table grows unboundedly without periodic cleanup (sweeper prunes delivered events after 7 days)
- Adds one DB round-trip per ingest; acceptable at expected IOC rates
