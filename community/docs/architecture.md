# Architecture

Community is a three-tier application:

```
Browser (React + Vite)
       ↓ HTTP/JSON
Go API (net/http, port 8090)
       ↓ pgx/v5
PostgreSQL 16
       ↓ HMAC-signed POST
CITADEL (evidence ledger)
```

## Key design decisions

- **No ORM** — raw SQL via `pgx/v5` for full control and performance.
- **Full-text search** — PostgreSQL `tsvector` `GENERATED ALWAYS AS STORED` column; no Elasticsearch dependency.
- **JWT auth** — HS256, same pattern as all opensecstack platforms; roles: viewer < author < moderator < admin.
- **Citadel emission** — `community.post.published` events are emitted on publish; dry-run by default in dev.
- **Reactions** — `UNIQUE (post_id, user_id, kind)` constraint enforces idempotency at DB level.
- **Threaded comments** — `parent_id` self-reference; no depth limit enforced server-side.
