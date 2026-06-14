# OpenScrub Data Model

OpenScrub has **two** data layers, and that distinction is the most
important thing to internalise before touching the codebase:

1. **Persistent control-plane state** lives in PostgreSQL 16. The
   `rules` table is the **source of truth** for what should be
   blocked, rate-limited, or SYN-cookied.
2. **Ephemeral data-plane state** lives in kernel BPF maps. The XDP
   program reads these maps on every packet; the maps are
   **derived** from the Postgres rows by the Go control plane. They
   are not authoritative — a fresh kernel after a host reboot has
   empty maps until the control plane reconciles them from
   Postgres.

This document covers both layers and the synchronisation contract
between them. For migration tooling see
[migrations.md](migrations.md). For performance budgets see
[performance.md](performance.md).

---

## Layer 1 — PostgreSQL schema

The full initial schema is in
[`migrations/0001_init.up.sql`](../migrations/0001_init.up.sql).
Three tables, no extensions beyond `pgcrypto` (for `gen_random_uuid`).

### `rules`

The active mitigation set. Every row corresponds to either an entry
in a BPF map (blocklist / ratelimit / syncookie listener) or, for
expired rows that the sweeper has not yet processed, a *pending
withdrawal* from a map.

```sql
CREATE TABLE rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type         TEXT NOT NULL CHECK (type IN ('blocklist', 'ratelimit', 'syncookie')),
    cidr         CIDR,
    pps          INTEGER,
    port         INTEGER CHECK (port IS NULL OR (port > 0 AND port < 65536)),
    ttl_seconds  INTEGER NOT NULL CHECK (ttl_seconds > 0),
    source       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    created_by   UUID,
    CONSTRAINT blocklist_requires_cidr
        CHECK (type <> 'blocklist' OR cidr IS NOT NULL),
    CONSTRAINT ratelimit_requires_cidr_and_pps
        CHECK (type <> 'ratelimit'
            OR (cidr IS NOT NULL AND pps IS NOT NULL AND pps > 0)),
    CONSTRAINT syncookie_requires_port
        CHECK (type <> 'syncookie' OR port IS NOT NULL)
);
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key. Echoed in CITADEL `rule_change` events. |
| `type` | TEXT | One of `blocklist`, `ratelimit`, `syncookie`. CHECK-enforced. |
| `cidr` | CIDR (nullable) | IPv4 or IPv6 prefix. Required for blocklist and ratelimit. Postgres normalises to network address on insert (`198.51.100.5/24` → `198.51.100.0/24`). |
| `pps` | INTEGER (nullable) | Packets-per-second cap. Required for ratelimit; rejected for other types at the Go layer (see [`internal/rules/rule.go`](../internal/rules/rule.go) `Validate`). |
| `port` | INTEGER (nullable) | TCP destination port. Required for syncookie; range-checked 1..65535. |
| `ttl_seconds` | INTEGER | Lifetime of the rule. Capped at 30 days at the Go layer. |
| `source` | TEXT | `operator`, `threatflow`, or `system`. See `rules.SourceXxx` constants. |
| `created_at` | TIMESTAMPTZ | Defaulted by Postgres. |
| `expires_at` | TIMESTAMPTZ | `created_at + ttl_seconds`. Set by [`rule_store.go`](../internal/db/rule_store.go) at insert time so the sweeper can index on it directly. |
| `created_by` | UUID (nullable) | JWT subject of the operator who created the rule. NULL for ThreatFlow / system rules. |

**Indexes**:

| Index | Columns | Use |
|---|---|---|
| `idx_rules_expires_at` | `(expires_at)` | TTL sweep — `DeleteExpired` does a range scan on this |
| `idx_rules_source` | `(source)` | Audit / "what did ThreatFlow add" filters |
| `idx_rules_type` | `(type)` | List filter on `GET /api/v1/rules?type=` |
| `idx_rules_cidr_gist` | GIST `(cidr inet_ops)` partial WHERE NOT NULL | Containment queries (`cidr && '10.0.0.0/8'`) — used by overlap checks |
| `idx_rules_port` | `(port)` partial WHERE NOT NULL | syncookie listener lookup |

**Retention**: rules are deleted when their TTL elapses
([`SweepExpired`](../internal/rules/service.go)). There is no audit
copy in this table — the audit trail lives in CITADEL via the
`openscrub.rule_change` event emitted on every transition.

### `mitigations`

Observed drop / ratelimit windows. One row per (rule, src_ip)
window. Drives the CITADEL evidence stream — the `state` column
moves `pending → sent` once CITADEL accepts the event, or
`pending → failed` after retries are exhausted.

The schema below is the **final** state after migration 0002
([`migrations/0002_mitigation_no_cascade.up.sql`](../migrations/0002_mitigation_no_cascade.up.sql)),
which (a) made `rule_id` nullable, (b) flipped the FK from
`ON DELETE CASCADE` to `ON DELETE SET NULL`, (c) added a snapshot
of the rule (`rule_cidr`, `rule_type`, `rule_source`) captured at
insertion time, and (d) replaced the boolean `emitted` flag with a
proper state machine plus retry bookkeeping.

```sql
-- 0001 + 0002 + 0003 combined effective shape:
CREATE TABLE mitigations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID REFERENCES rules (id) ON DELETE SET NULL,  -- nullable
    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ,
    packets_dropped BIGINT NOT NULL DEFAULT 0,
    bytes_dropped   BIGINT NOT NULL DEFAULT 0,  -- always 0 in v1.0.0 (see note)
    src_ip          INET,
    emitted         BOOLEAN NOT NULL DEFAULT FALSE,  -- back-compat readers
    -- Rule snapshot (populated at INSERT, survives parent rule deletion):
    rule_cidr       CIDR,
    rule_type       TEXT,
    rule_source     TEXT,
    -- State machine + retry bookkeeping:
    state           TEXT NOT NULL DEFAULT 'pending'
                       CHECK (state IN ('pending', 'sent', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    sent_at         TIMESTAMPTZ,
    -- Migration 0003 — counter-baseline snapshot captured at the
    -- start of each evidence window. The lifecycle reads the global
    -- eBPF packets_dropped counter at rule-create time and stores it
    -- here; finalize subtracts it to derive the window delta written
    -- to packets_dropped above. See
    -- internal/rules/mitigation_lifecycle.go for the over-attribution
    -- caveat with concurrent rules.
    start_packets_dropped BIGINT NOT NULL DEFAULT 0,
    start_bytes_dropped   BIGINT NOT NULL DEFAULT 0
);
```

> **`bytes_dropped` in v1.0.0:** the eBPF data plane in v1.0.0 only
> exposes packet counters — there is no per-byte accumulator yet. The
> lifecycle therefore writes `0` to `bytes_dropped` (and
> `start_bytes_dropped`) on every row. The column is kept in the
> schema so the v1.1 per-rule counter map can populate it without a
> follow-up migration; treat any non-zero value on a v1.0.0
> deployment as a bug. The wire `int64` type is unchanged — only the
> semantics narrow across the v1.x series. Tracked as ROADMAP
> "v1.1.0 — per-rule counters".

**Indexes**:

| Index | Columns | Use |
|---|---|---|
| `idx_mitigations_rule` | `(rule_id)` | join to `rules` (nullable after 0002) |
| `idx_mitigations_started` | `(started_at DESC)` | timeline reads (`GET /api/v1/mitigations?since=…`) |
| `idx_mitigations_state_started` | `(state, started_at)` | watcher hot path: cheap lookup of pending rows for emission |
| `idx_mitigations_emitted_started` | `(emitted, started_at)` | back-compat for callers still keying off the boolean |

**FK behaviour**: `rule_id → rules(id) ON DELETE SET NULL`. Before
0002 the FK cascaded, which destroyed in-flight evidence whenever
an operator deleted the parent rule (or the TTL sweep removed it)
mid-flight. Post-0002 the parent-rule deletion only nulls
`rule_id` on the mitigation row; the snapshot columns
(`rule_cidr`, `rule_type`, `rule_source`) preserve enough evidence
for the CITADEL event payload to be built and signed even after the
rule itself is gone. **`rule_id` is nullable** — readers must not
assume it is set.

**Lifecycle** (see
[`mitigation_store.go`](../internal/db/mitigation_store.go) and
[`citadel/mitigation_watcher.go`](../internal/citadel/mitigation_watcher.go)):

1. `Insert` — `ended_at = NULL`, counters at 0, snapshot columns
   captured from the parent rule, `state = 'pending'`, `attempts = 0`.
2. `Close` — set `ended_at`, final counters. State stays `pending`.
3. Watcher attempts emission. On 2xx: `state = 'sent'`,
   `sent_at = now()`, the legacy `emitted` boolean flips `TRUE`.
   On transient error: state stays `pending`, `attempts++`,
   `last_error` recorded.
4. After retry exhaustion: `state = 'failed'`, `last_error`
   pinned, no further attempts. Operators audit failed rows out of
   band.

#### Mitigation lifecycle state machine

```
                      Insert
                        │
                        ▼
                   ┌─────────┐
                   │ pending │◄──── retry (attempts++, last_error set)
                   └─────────┘
                    │       │
            CITADEL │       │ retry budget
              2xx   │       │  exhausted
                    ▼       ▼
                ┌──────┐ ┌────────┐
                │ sent │ │ failed │
                └──────┘ └────────┘
```

`pending` is the only mutable state from the watcher's perspective:
it either advances to `sent` (success path) or to `failed` (after
the configured retry budget). Rows in `failed` are kept for audit;
they are never automatically retried, but the boolean `emitted`
column stays `FALSE` so legacy back-compat readers still see them
as "not yet emitted".

### `ioc_ingest_log`

Audit trail for ThreatFlow IOC bundle pulls.

```sql
CREATE TABLE ioc_ingest_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source        TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    count         INTEGER NOT NULL,
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, bundle_sha256)
);
```

The `UNIQUE (source, bundle_sha256)` is load-bearing — the IOC
puller relies on the `23505` unique-violation error (translated to
`ErrIOCBundleAlreadyIngested` in
[`ioc_log_store.go`](../internal/db/ioc_log_store.go)) to skip
already-applied bundles cheaply, without fetching first.

**Index**: `idx_ioc_ingest_log_at (ingested_at DESC)` for the
"last successful pull" query exposed on `/api/v1/health`.

---

## Layer 2 — BPF map schema

Five maps, declared in
[`ebpf/openscrub.bpf.c`](../ebpf/openscrub.bpf.c) and named via the
constants in
[`rust/dataplane/src/lib.rs`](../rust/dataplane/src/lib.rs).

| Map | Type | Key | Value | Max entries | Source |
|---|---|---|---|---|---|
| `blocklist_v4` | `LPM_TRIE` | `(prefixlen, __u32 addr)` | `__u8 = 1` | 100 000 | rules.type='blocklist', IPv4 cidr |
| `blocklist_v6` | `LPM_TRIE` | `(prefixlen, __u8 addr[16])` | `__u8 = 1` | 50 000 | rules.type='blocklist', IPv6 cidr |
| `ratelimit` | `HASH` | `__u32` (IPv4 src) | `struct ratelimit_value` (24 B) | 100 000 | rules.type='ratelimit' |
| `stats` | `PERCPU_ARRAY` | `__u32` (enum stat_kind) | `__u64` | 5 | populated by the XDP program |
| `syncookie_listeners` | `HASH` | `__u16` (dst port, host order) | `__u8 = 1` | 4 096 | rules.type='syncookie' |

### Why `HASH`, not `PERCPU_HASH`, for `ratelimit`

This is intentionally documented at the C-source level; quoting
[`ebpf/openscrub.bpf.c`](../ebpf/openscrub.bpf.c) verbatim:

> The token bucket is shared across CPUs and therefore intentionally
> racy: concurrent `ratelimit_allow()` calls on the same src IP race
> on `rv->tokens` / `rv->last_refill_ns`. The race is bounded (we
> only over- or under-shoot by ~NCPU tokens per refill window) and
> acceptable for a coarse PPS limiter; using `PERCPU_HASH` would
> multiply the configured PPS by NCPU and break the contract the
> operator sees in the API.

If an operator sets `pps=1000` for `203.0.113.7`, they expect ~1000
PPS to leak through, not `1000 * num_cores`. `HASH` keeps that
contract; the per-refill race is bounded and acceptable.

### `stats` is `PERCPU_ARRAY`

The five counters
(`STAT_PACKETS_PASSED`, `STAT_PACKETS_DROPPED`,
`STAT_PACKETS_RATELIMITED`, `STAT_PACKETS_MALFORMED`,
`STAT_SYN_COOKIES_SENT`) are write-hot on every packet.
`PERCPU_ARRAY` eliminates cross-CPU contention; userspace sums the
per-CPU values via [`StatsReader`](../rust/dataplane/src/stats.rs).

### LPM trie value type

Both blocklists store `__u8 = 1` as the value (presence is the
signal). The kernel's LPM trie still requires a value, so we use
the smallest meaningful one. `BPF_F_NO_PREALLOC` is set so the
trie allocates lazily — important because most deployments will
populate well under the 100k cap.

---

## Sync model (Postgres ↔ BPF)

The Go control plane is the only writer to BPF maps; the XDP
program is the only reader. The orchestration is in
[`internal/rules/service.go`](../internal/rules/service.go), and
the **ordering of writes is intentional**.

### Create — Postgres first, dataplane second

```text
Service.Create
 ├─ repo.Insert          (Postgres write)
 ├─ installInPlane       (BPF map write)
 │    └─ on error: repo.Delete (rollback)
 └─ emitChange(insert)   (CITADEL)
```

Why this order: the rule must be **durable** before it has any
effect on traffic. If the host crashes between `Insert` and
`installInPlane`, the next reconciliation pass installs the rule
from Postgres — no traffic was wrongly affected and no operator
intent was lost. If we wrote the BPF map first and crashed before
the Postgres row landed, we'd be silently dropping traffic that
nobody can find a record of, and a reboot would un-drop it without
explanation.

On dataplane error, `Insert` is rolled back so the two layers do
not disagree.

### Delete — dataplane first, Postgres second

```text
Service.Delete
 ├─ removeFromPlane      (BPF map write)
 ├─ repo.Delete          (Postgres write)
 └─ emitChange(withdraw) (CITADEL)
```

Why the **opposite** order: the inverted failure mode is
asymmetric. A crash between `repo.Delete` and `removeFromPlane`
would leave a BPF entry that **continues dropping traffic** with no
matching row in Postgres — silent traffic loss with no UI surface
and no audit row to explain it. By yanking from the data plane
first, the worst-case post-crash state is a stale Postgres row for
a rule already removed from the kernel. The next sweep reconciles
that cleanly.

This is captured in the doc-comment on `Service`:

> on Delete we yank from the data plane *before* deleting the row
> so a crash mid-call leaves a stale row (recoverable via the next
> sweep) rather than an unblocked-but-believed-blocked CIDR (silent
> traffic).

### Sweep — TTL-driven, same order as Delete

`SweepExpired` runs `DeleteExpired` (Postgres) which `RETURNING`s
the rows it removed, then iterates each removed rule and calls
`removeFromPlane`. This is the one case where Postgres goes first
in a withdrawal — but the kernel state is still strictly more
permissive than Postgres at every intermediate moment (a sweep
crash leaves a kernel entry whose Postgres row is gone; the next
boot's reconcile handles it).

---

## Capacity model

The total locked kernel memory budget is the sum of the BPF maps.
Approximate working figures (real kernel allocations vary by
implementation; see `bpftool map show` for live numbers):

| Map | Per-entry (approx) | Max entries | Approx max bytes |
|---|---|---|---|
| `blocklist_v4` | LPM key 8 B + value 1 B + node overhead ~80 B | 100 000 | ~9 MB |
| `blocklist_v6` | LPM key 20 B + value 1 B + node overhead ~120 B | 50 000 | ~7 MB |
| `ratelimit` | hash key 4 B + value 24 B + bucket overhead ~50 B | 100 000 | ~8 MB |
| `syncookie_listeners` | 2 B + 1 B + overhead | 4 096 | ~0.5 MB |
| `stats` | 8 B × NCPU × 5 entries | 5 | <1 KB |

**Total ceiling: ~24 MB of locked kernel memory** when all caps
are full. These figures are approximate and conservative — the
LPM trie node overhead in particular depends on tree fan-out at
runtime. Run `bpftool map show id <id>` against a populated host
to get the live `bytes_memlock` figure. Operators must set
`memlock` ulimit (or `RLIMIT_MEMLOCK`) to comfortably exceed this;
see [deployment.md](deployment.md) for the unit-file knobs.

---

## See also

- [migrations.md](migrations.md) — schema change procedure
- [architecture.md](architecture.md) — control-plane / data-plane split
- [performance.md](performance.md) — per-feature data-plane cost
- [citadel-integration.md](citadel-integration.md) — `rule_change` and `mitigation` events
- [threatflow-integration.md](threatflow-integration.md) — `ioc_ingest_log` semantics
