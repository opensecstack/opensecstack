# ADR 003: PostgreSQL as Token Store

**Status**: Accepted
**Date**: 2024-01-15
**Deciders**: sinauth core team

## Context

sinauth needs to store short-lived authorization codes, long-lived refresh tokens, SSO sessions, and consent grants. These must be queryable, revocable, and durable. Several storage options were considered: PostgreSQL, Redis, and in-memory (process-local).

## Decision

We use PostgreSQL as the sole persistent store for all sinauth state, including authorization codes, refresh tokens, SSO sessions, and consent records.

## Reasons

### Consistent with the rest of the SIN stack

Every SIN platform already uses PostgreSQL as its primary database. Introducing Redis as a sinauth dependency would add an operational requirement that is not present anywhere else in the stack: PostgreSQL replication, backup, and monitoring tooling is already well-understood by the team. Redis would require separate expertise, separate backup procedures, and separate monitoring.

### Enables revocation

Refresh tokens stored in PostgreSQL can be revoked at any time: set `revoked = true` on the row. The next use of the refresh token immediately fails the database lookup.

In-memory storage does not survive process restarts. Purely JWT-based refresh tokens cannot be revoked before expiry without a denylist.

Redis can support revocation via key deletion, but adds the operational complexity described above.

### Atomic operations with pgx

PostgreSQL with `pgx` (the Go driver used throughout SIN) supports atomic operations via transactions. Authorization code consumption — the critical step where a code is marked `used = true` — is performed atomically. A code cannot be used twice even under concurrent requests.

```sql
-- Atomic: read and mark used in one transaction
UPDATE authorization_codes
SET used = true
WHERE code = $1 AND used = false AND expires_at > now()
RETURNING user_id, client_id, scopes, code_challenge, ...
```

This atomicity is trivial in PostgreSQL and would require careful WATCH/MULTI/EXEC in Redis.

### Durable by default

PostgreSQL writes are durable: tokens survive process restarts, crashes, and server reboots. Users are not logged out by a sinauth restart.

Redis in default (non-AOF) configuration is not durable — a restart loses all data. Users would be logged out on every sinauth deployment. AOF (append-only file) persistence adds durability to Redis but further increases operational complexity.

### No additional infrastructure

Running sinauth requires only: a Go binary and a PostgreSQL database. No Redis, no Memcached, no external session store. This keeps the deployment surface minimal and the operational burden on the SIN team low.

## Trade-offs

### Performance

Redis is faster than PostgreSQL for simple key-value lookups. However:
- Authorization code exchange happens once per login, not per request. Latency here is not critical.
- Refresh token exchange happens at most once per hour per user. Also not a hot path.
- Token verification (the hot path) is done locally without any database call — platforms verify RS256 signatures against the cached JWKS.

The token paths in sinauth are not performance-sensitive enough to justify Redis.

### Scalability

PostgreSQL can handle sinauth's expected load (thousands of logins/day across 10 platforms) comfortably on a single instance. If sinauth ever reaches a scale where PostgreSQL is a bottleneck for auth code and refresh token lookups, Redis can be added as a cache layer at that point — it is not needed now.

## Consequences

- sinauth's only infrastructure dependency is PostgreSQL (already required).
- All token state (codes, refresh tokens, sessions, consents) is in PostgreSQL tables.
- Refresh token revocation is a simple `UPDATE` query.
- Authorization code consumption is atomic via `UPDATE ... RETURNING`.
- Refresh tokens are stored as `SHA-256(token)` — the raw token is never persisted.
- Expired records are cleaned up by a background goroutine using periodic `DELETE WHERE expires_at < now()`.
