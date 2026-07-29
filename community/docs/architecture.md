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
- **Citadel WORM emission** — `community.post.published` and `community.user.deleted` events are appended to CITADEL's WORM chain via `POST /api/v1/worm/emit`; dry-run by default in dev. This is audit-only evidence, not an authorization check.
- **Citadel MARSHAL governance for GDPR deletion** — before a user account is actually deleted, a Kerkese is submitted to CITADEL MARSHAL (Actor = the user being deleted, Verifier = the approving admin) and a REFUSE/HARD_STOP verdict blocks the deletion. A distinct admin must also explicitly approve a pending deletion request at the application level before this check is ever reached. See the README's [GDPR & Account Deletion](../README.md#gdpr--account-deletion) section.
- **Reactions** — `UNIQUE (post_id, user_id, kind)` constraint enforces idempotency at DB level.
- **Threaded comments** — `parent_id` self-reference; no depth limit enforced server-side.
