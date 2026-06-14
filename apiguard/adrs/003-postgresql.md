# ADR-003: Use PostgreSQL for Scan Persistence

## Status

Accepted

## Context

APIGuard needs to persist scan records, finding records, API inventory, audit logs, and API keys across restarts and across multiple instances. The persistence layer must support:

- Multiple concurrent scanner instances writing results simultaneously
- Dashboard queries over scan history and finding trends
- Audit log chain integrity (each entry references the hash of the previous entry)
- Flexible evidence storage (finding evidence is JSON of arbitrary structure)
- Multi-tenant isolation (optional future requirement)

## Decision

Use PostgreSQL 15+ as the sole persistent store.

Specific implementation choices:

- **Driver**: `pgx/v5` (native PostgreSQL protocol, no database/sql abstraction overhead)
- **Query layer**: `sqlx` for named parameters and struct scanning
- **Migrations**: `golang-migrate` with SQL migration files in `migrations/`
- **JSONB**: Finding evidence stored as PostgreSQL JSONB for flexible querying without a separate document store
- **Auto-migrate**: Enabled by default (`database.auto_migrate: true`), can be disabled for externally managed migration workflows

## Rationale

- **ACID guarantees** ensure scan records and findings are either fully written or not at all. A scan that is interrupted mid-write does not produce partially-recorded results.
- **JSONB** eliminates the need for a separate document store (MongoDB, Elasticsearch) for evidence. PostgreSQL's JSONB indexing is sufficient for dashboard queries over evidence content.
- **Row-level security** is available for future multi-tenant isolation — each organisation's scan data can be isolated at the database level without application-layer sharding.
- **Mature ecosystem**: pgx, sqlx, and golang-migrate are stable, well-maintained, and widely deployed in production.
- **Horizontal scaling**: Multiple APIGuard instances connect to the same PostgreSQL instance. PostgreSQL handles concurrent writes correctly via its MVCC model.
- **Audit log integrity**: The `chain_hash` field in `audit_log` is computed as SHA-256 of the entry content concatenated with `prev_hash`. PostgreSQL's ACID guarantees that chain entries are written in order, maintaining the integrity chain.

## Alternatives Considered

- **SQLite**: Rejected. Does not support multiple concurrent writers from separate processes. Cannot be used in a horizontally-scaled deployment.
- **MongoDB**: Rejected. No ACID transactions for the audit log chain. JSONB in PostgreSQL handles the flexible evidence storage requirement without introducing a second storage system.
- **MySQL/MariaDB**: Rejected. pgx's native protocol implementation is significantly faster than MySQL drivers. PostgreSQL's JSONB support is more capable than MySQL's JSON type. Less common in the security tooling ecosystem.
- **Redis-only**: Rejected. Redis is used for the scan job queue and rate limiting, not for durable storage. Scan evidence must survive Redis restarts.
- **CockroachDB/Spanner**: Rejected for this phase. Distributed SQL adds operational complexity with no benefit at current scale. The architecture supports migration to a distributed SQL layer later if needed.

## Consequences

- PostgreSQL must be provisioned for every non-ephemeral deployment. For CLI-only usage (no dashboard, no persistence), the database is not required.
- The `docker-compose.yml` provides PostgreSQL out of the box for development and small deployments.
- Contributors must understand basic PostgreSQL administration for production deployments.
- Migration management must be handled carefully in multi-instance deployments — only one instance should run migrations at startup, or use `database.auto_migrate: false` and run migrations externally.
