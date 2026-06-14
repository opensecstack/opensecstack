# CITADEL Data Model

Schema reference for CITADEL's PostgreSQL 16 database. All tables and
types are declared in [migrations/001_initial.sql](../migrations/001_initial.sql);
this document explains the *why* behind each design decision.

## Tables at a glance

| Table | Purpose | Append-only? |
|---|---|---|
| `worm_entries` | The WORM audit chain | **Strictly** |
| `chain_anchors` | Ed25519 signatures over the WORM chain | Strictly |
| `sessions` | Active authentication sessions for Gate 1 / Gate 3 | Mutable |
| `rate_limit_counters` | Per-user action counts for AUGUR rule_02 | Mutable |
| `schema_migrations` | Migration bookkeeping | Append-only by convention |

Only two tables are WORM-semantics strict. The others are mutable
operational state that mirrors data already recorded in the chain —
if they are truncated, they can be rebuilt from the WORM entries.
The chain itself cannot be rebuilt from anything.

## `worm_entries`

See [worm-log.md](./worm-log.md) for the full column-by-column
reference. Summary:

- **Primary key:** `id` (UUID, but not used for chain math)
- **Unique:** `sequence_num` (monotonic from 1)
- **Indexes:** `(ts_utc)`, `(event_type, project_id)`, `(source, ts_utc)`
- **Append model:** `LOCK TABLE ... EXCLUSIVE MODE` per insert
- **Size estimate:** ~1 KiB per entry; 1 M entries ≈ 1 GB

## `chain_anchors`

See [chain-anchor.md](./chain-anchor.md).

- **Primary key:** `id` (UUID)
- **Foreign key:** `sequence_num → worm_entries.sequence_num`
- **Index:** `(sequence_num)` for fast "which anchor covers entry N?"
  queries
- **Size:** ~160 bytes per anchor; at `CITADEL_ANCHOR_INTERVAL=100`,
  1 anchor per ~100 entries, i.e. anchor table ≈ 0.16% of WORM table
  size

## `sessions`

Backs Gate 1 (AuthN). A session row is created when a user
authenticates and deleted or expires on logout / TTL.

```sql
CREATE TABLE sessions (
    user_id    BIGINT      NOT NULL PRIMARY KEY,
    role       TEXT        NOT NULL,
    role_group TEXT        NOT NULL,   -- for Gate 3 NDS
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
```

- **Role vs role_group:** `role` is fine-grained (`soc-analyst`);
  `role_group` is the Gate-3 equivalence class (`security`). Two
  different analysts could share a role group and would therefore fail
  SoD.
- **TTL:** enforced at query time (`SessionExists` filters by
  `expires_at > now()`). Expired rows are garbage-collected by a
  background worker — they are not load-bearing past expiry.
- **No password material.** CITADEL does not store credentials;
  session tokens are minted externally and signed with the upstream
  IdP's key.

## `rate_limit_counters`

Backs AUGUR rule_02 (high-frequency detection). Counts actions per
user per 5-minute window.

```sql
CREATE TABLE rate_limit_counters (
    user_id     BIGINT      NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    action_count INT        NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, window_start)
);
```

- **Updated by:** the Gate 5 WORM append path increments
  `rate_limit_counters.action_count` for the actor, upserting the
  window.
- **GC'd by:** background worker removing rows with
  `window_start < now() - 10 minutes` (twice the observation window,
  for safety).
- **Not load-bearing past GC.** If the counter is missing, AUGUR
  rule_02 falls through — same as if the actor had made zero prior
  actions. This is deliberate: rule_02 is advisory, not gating.

## `schema_migrations`

Migration bookkeeping. A single row per applied migration.

```sql
CREATE TABLE schema_migrations (
    version    INT         NOT NULL PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- **The hard rule from CONTRIBUTING:** never modify an applied
  migration. Add `002_*.sql`, `003_*.sql`, …, each one idempotent.
- **Idempotency:** `CREATE ... IF NOT EXISTS`, `ADD COLUMN ... IF NOT
  EXISTS`. Re-applying a migration against an up-to-date DB logs
  "no-op" and exits 0.

## Entity relationships

```
                 ┌──────────────────┐
                 │  worm_entries    │◄──── every cross-platform event
                 │  (strictly WORM) │
                 └───────┬──────────┘
                         │ sequence_num
                         ▼
                 ┌──────────────────┐
                 │  chain_anchors   │◄──── Ed25519 signatures
                 │  (strictly WORM) │
                 └──────────────────┘

                 ┌──────────────────┐
                 │     sessions     │◄──── Gate 1 AuthN
                 │  (mutable)       │       Gate 3 NDS (role_group)
                 └──────────────────┘

                 ┌──────────────────────┐
                 │ rate_limit_counters  │◄── Gate 4 AUGUR rule_02
                 │  (mutable, GC'd)     │
                 └──────────────────────┘
```

Notice: the WORM chain has **no foreign keys into** `sessions` or
`rate_limit_counters`. The mutable tables reference the chain, not
vice-versa. Dropping the mutable tables does not break the chain;
dropping the chain voids every downstream evidence claim.

## Payload JSON schemas

Each `event_type` has an implicit JSON shape in `worm_entries.payload`.
CITADEL does not enforce these schemas at write time — the chain
stores what the caller sent — but cross-platform consumers must
produce compliant payloads. Canonical shapes:

### `event_type = marshal.decision`

```json
{
  "kerkese":      { "...": "see kerkese-spec.md" },
  "outcome":      "EXECUTE | REFUSE | HARD_STOP",
  "gates": [
    { "gate": 1, "name": "AuthN", "status": "PASS|FAIL|WARN|HARD_STOP", "latency_ms": 0.84 }, ...
  ],
  "reasons":      ["AUTHZ_FAIL: ..."],
  "execution_id": "uuid",
  "ts_utc":       "..."
}
```

### `event_type = incident.created` (from IRFlow)

```json
{
  "incident_id": "inc_...",
  "severity":    "P1|P2|P3|P4",
  "title":       "...",
  "source":      "irflow",
  "project_id":  "...",
  "ts_utc":      "..."
}
```

### Other event types

IRFlow, ThreatFlow, APIGuard, NIS2 Compass each define their own
`event_type` namespaces. Per-platform documentation lists them. The
key invariant: `project_id` is always present, `ts_utc` is always
present, and the rest of the payload is consumer-defined.

## Indexing strategy

- **Time-range queries** (`WHERE ts_utc BETWEEN ? AND ?`): the
  `(ts_utc)` index on `worm_entries` is adequate up to ~100 M entries.
  Beyond that, range-partitioning by month is the planned scale
  strategy (v1.2).
- **Per-project queries** (`WHERE project_id = ? AND event_type = ?`):
  the `(event_type, project_id)` index on `worm_entries` supports
  auditor workflows without scanning.
- **Chain walk**: ordered by `sequence_num`; the unique index serves.
  Chain verification is O(N) scans; no index accelerates it because
  it must visit every row.

## Back-of-envelope sizing

| Metric | Value |
|---|---|
| WORM entry size (avg payload 700 B) | ~1 KiB |
| WORM entries per year at 10 events/sec | 315 M |
| WORM disk per year | ~315 GiB |
| Anchor interval | 100 |
| Anchors per year | 3.15 M |
| Anchor disk per year | ~0.5 GiB |

At 24/7 10 events/sec — a moderately-sized SOC integrating MARSHAL
for every action — a year of evidence fits on modern SSDs without
trouble. Cold archival becomes attractive beyond 3-5 years.

## Related

- [WORM log](./worm-log.md) — core append semantics
- [Chain anchor](./chain-anchor.md) — signature mechanics
- [AUGUR](./augur.md) — consumer of `rate_limit_counters`
- [Architecture](./architecture.md) — data model in the full system context
