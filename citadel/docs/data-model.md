# CITADEL Data Model

Schema reference for CITADEL's PostgreSQL 16 database. All tables and
types are declared in [migrations/001_initial.sql](../migrations/001_initial.sql);
this document explains the *why* behind each design decision.

## Tables at a glance

| Table | Purpose | Append-only? |
|---|---|---|
| `worm_entries` | The WORM audit chain | **Strictly** |
| `chain_anchors` | Ed25519 signatures over the WORM chain | Strictly |
| `signing_keys` | Registered per-user Ed25519 public keys for Gate 1 / Gate 3 signature checks | Mutable |
| `rate_limit_counters` | Per-user action counts for AUGUR rule_02 | Mutable |
| `permify_role_action_snapshot` | Local snapshot of Permify-derived role→action policy for Gate 2's optional soft-check | Mutable |
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

## `signing_keys`

Backs the Ed25519 non-repudiation checks in Gate 1 (AuthN) and Gate 3
(NDS) — see [ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md).
CITADEL itself has no local session table: Gate 1/Gate 3 authenticate
the caller by verifying a sinauth-issued bearer JWT directly against
sinauth's JWKS (`internal/auth.SinauthVerifier`), then check
`SigOperator`/`SigVerifier` on the Kerkese against the registrant's
active key here. See [ADR-005](../adrs/005-sinauth-identity-bridge.md)
for why the identity side dropped the old local session model.

```sql
CREATE TABLE signing_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     TEXT        NOT NULL,   -- sinauth UUID, since migration 004
    key_id      TEXT        NOT NULL,
    public_key  TEXT        NOT NULL,   -- hex, 64 chars (32-byte Ed25519 public key)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    UNIQUE (user_id, key_id)
);
```

- **`user_id` is the sinauth UUID**, not a local integer identity.
  Migration `004_sinauth_identity.sql` widened this column from
  `BIGINT` to `TEXT` to hold it.
- **Registration:** `POST /api/v1/keys/register` requires a live
  sinauth token (`token` field) rather than a session — the caller
  proves who they are with that token, and the key is bound to its
  `sub`.
- **Active key:** at most one row per `user_id` should have
  `revoked_at IS NULL`, enforced in application code
  (`RegisterKey`), not a DB constraint, so rotation (register-new,
  then revoke-old) can proceed in two steps.
- **No password material.** CITADEL does not store credentials;
  user authentication is sinauth's concern — this table only holds
  the public half of a signing keypair.

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

## `permify_role_action_snapshot`

Local snapshot of Permify-derived role→action_type coverage, read by
MARSHAL Gate 2 (AuthZ)'s optional soft-check — see
[ADR-007](../adrs/007-permify-gate2-snapshot.md). Gate 2 must never
make a live synchronous call to Permify per-request (it runs in the
hot path of every governed action across the ecosystem, at
~microsecond latency); instead it reads this table's in-memory copy,
refreshed on an interval (`citadel.permify_sync_interval`, default
`5m`) by `internal/permifysync.Syncer`.

```sql
CREATE TABLE permify_role_action_snapshot (
    role        TEXT        NOT NULL,
    action_type TEXT        NOT NULL,
    allowed     BOOLEAN     NOT NULL,
    synced_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role, action_type)
);
```

- **Migration:** `005_permify_policy_snapshot.sql`.
- **Expected to be empty/near-empty today.** As of this migration,
  sinauth's Permify schema (`sinauth/permify/schema.perm`) models
  organization/group/client_role membership, not CITADEL's governed
  action-type vocabulary (`API_SCAN_INITIATE`, `INCIDENT_CREATE`,
  ...) — so this table is expected to sync empty until the schema is
  extended in a later phase. This is documented current scope, not a
  bug: Gate 2's existing `rbacMap` check remains the unconditionally
  enforced safety net regardless of what this table contains, and an
  empty snapshot just means the Permify sub-check passes everything
  (see [Known limitations](./known-limitations.md)).
- **Not load-bearing on its own.** A row here only ever adds a soft
  `WARN`-until-`EnforcePermifyAuthz`-is-enabled signal on top of
  `rbacMap` (`internal/marshal/marshal.go`'s `gate2AuthZ`); it can
  never grant access `rbacMap` denies.

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
                 │   signing_keys   │◄──── Gate 1 AuthN (SigOperator)
                 │  (mutable)       │       Gate 3 NDS (SigVerifier)
                 └──────────────────┘
                   (identity itself is verified against a live
                    sinauth JWT, not a local table — see ADR-005)

                 ┌──────────────────────┐
                 │ rate_limit_counters  │◄── Gate 4 AUGUR rule_02
                 │  (mutable, GC'd)     │
                 └──────────────────────┘
```

Notice: the WORM chain has **no foreign keys into** `signing_keys` or
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
