# OpenCSIRT Data Model

> v1.0.0. Initial schema from
> [`migrations/0001_init.up.sql`](../migrations/0001_init.up.sql).
> The Go API's [`internal/db/`](../internal/db/) packages are the
> canonical implementations. For migration tooling see
> [migrations.md](migrations.md); for performance considerations see
> [performance.md](performance.md).

OpenCSIRT stores all control-plane state in PostgreSQL 16. The
schema has eight tables in v1.0.0; only the `uuid-ossp` extension is
required. There is no second data layer (unlike
[OpenScrub](../../openscrub/docs/data-model.md), which has BPF maps
under Postgres).

| Table | Owns | Implementation |
|---|---|---|
| [`constituencies`](#constituencies) | organisations the CSIRT serves | [`internal/db/constituency_store.go`](../internal/db/constituency_store.go) |
| [`incidents`](#incidents) | security incidents | [`internal/db/incident_store.go`](../internal/db/incident_store.go) |
| [`advisories`](#advisories) | CSAF 2.0 advisories | [`internal/db/advisory_store.go`](../internal/db/advisory_store.go) |
| [`peer_csirts`](#peer_csirts) | federated peer CSIRTs | [`internal/db/peer_store.go`](../internal/db/peer_store.go) |
| [`escalations`](#escalations) | incidents handed to peer CSIRTs | [`internal/db/peer_store.go`](../internal/db/peer_store.go) |
| [`citadel_outbox`](#citadel_outbox) | durable CITADEL event queue | [`internal/db/outbox_store.go`](../internal/db/outbox_store.go) |
| [`audit_log`](#audit_log) | read-side & non-CITADEL audit trail | [`internal/db/audit_store.go`](../internal/db/audit_store.go) |
| [`ioc_ingest_log`](#ioc_ingest_log) | ThreatFlow IOC pull bookkeeping | (puller) |

---

## constituencies

Organisations the CSIRT serves. Uniqueness is `(name, country)`.

```sql
CREATE TABLE constituencies (
    id                       uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                     text NOT NULL,
    sector                   text NOT NULL,
    country                  text NOT NULL,
    nis2_status              text NOT NULL CHECK (nis2_status IN ('essential', 'important', 'out_of_scope')),
    primary_contact_email    text NOT NULL,
    secondary_contact_email  text,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, country)
);

CREATE INDEX idx_constituencies_sector     ON constituencies(sector);
CREATE INDEX idx_constituencies_nis2_status ON constituencies(nis2_status);
```

| Column | Notes |
|---|---|
| `country` | ISO 3166-1 alpha-2 (validated at the API layer). |
| `nis2_status` | Drives Article 23 routing — only `essential` and `important` rows trigger a NIS2 Compass push on advisory publish. |
| `secondary_contact_email` | Nullable; used as a fallback for incident notifications. |

---

## incidents

Security incidents owned by a constituency.

```sql
CREATE TABLE incidents (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    constituency_id   uuid REFERENCES constituencies(id) ON DELETE SET NULL,
    source            text NOT NULL CHECK (source IN ('irflow', 'manual', 'abuse_mailbox', 'peer_csirt')),
    severity          text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaged', 'contained', 'closed')),
    title             text NOT NULL,
    description       text NOT NULL DEFAULT '',
    opened_at         timestamptz NOT NULL DEFAULT now(),
    closed_at         timestamptz,
    citadel_emitted   boolean NOT NULL DEFAULT false,
    metadata          jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_incidents_constituency_id ON incidents(constituency_id);
CREATE INDEX idx_incidents_status_opened   ON incidents(status, opened_at DESC);
CREATE INDEX idx_incidents_severity        ON incidents(severity);
```

**FK behaviour**: `constituency_id → constituencies(id) ON DELETE SET NULL`.
A constituency can be retired without destroying its incident
history — the row continues to exist with `constituency_id = NULL`
and the original `metadata` snapshot. This is the same evidence-
preservation pattern used by OpenScrub's `mitigations.rule_id`.

`citadel_emitted` is a fast-path boolean; the durable state lives
in [`citadel_outbox`](#citadel_outbox).

---

## advisories

CSAF 2.0 advisories. Drafted by `analyst`+, published by
`csirt_lead`+. Schema in [api.md](api.md#advisories); authoring
guide in [advisory-authoring-guide.md](advisory-authoring-guide.md).

```sql
CREATE TABLE advisories (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id       uuid REFERENCES incidents(id) ON DELETE SET NULL,
    csaf_id           text NOT NULL UNIQUE,
    csaf_version      text NOT NULL DEFAULT '2.0',
    csaf_doc          jsonb NOT NULL,
    state             text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'withdrawn')),
    tlp               text NOT NULL DEFAULT 'GREEN' CHECK (tlp IN ('CLEAR', 'GREEN', 'AMBER', 'RED')),
    title             text NOT NULL,
    summary           text NOT NULL DEFAULT '',
    published_at      timestamptz,
    published_by      uuid,
    citadel_emitted   boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_advisories_state        ON advisories(state);
CREATE INDEX idx_advisories_published_at ON advisories(published_at DESC NULLS LAST);
```

**FK behaviour**: `incident_id → incidents(id) ON DELETE SET NULL`.
An incident can be redacted without losing the published advisory
that referenced it; the CSAF document is self-contained in
`csaf_doc`.

**State transitions** (enforced at the API layer):

```
draft ──publish──▶ published ──withdraw──▶ withdrawn
                       │
                       └──── (terminal apart from withdraw)
```

`csaf_id` is `UNIQUE` — duplicates surface as `409 Conflict` from
the API. The convention is `OPENCSIRT-YYYY-NNNN`.

---

## peer_csirts

Federated peer CSIRTs (FIRST / TF-CSIRT counterparts). Trust
bootstrapped by [the handshake protocol](peer-csirt-handshake-protocol.md).

```sql
CREATE TABLE peer_csirts (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                text NOT NULL UNIQUE,
    jurisdiction        text NOT NULL,
    contact_endpoint    text NOT NULL,
    pgp_key             text,
    last_handshake_at   timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
```

`pgp_key` is the ASCII-armoured public key used for out-of-band
verification of the peer's HMAC key. `last_handshake_at` is updated
by the handshake job; absence beyond a configured threshold flags
the peer for re-validation.

---

## escalations

Incidents handed off to a peer CSIRT.

```sql
CREATE TABLE escalations (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    peer_id       uuid NOT NULL REFERENCES peer_csirts(id) ON DELETE RESTRICT,
    sent_at       timestamptz NOT NULL DEFAULT now(),
    ack_at        timestamptz,
    response      jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (incident_id, peer_id)
);

CREATE INDEX idx_escalations_incident ON escalations(incident_id);
```

**FK behaviour**:

- `incident_id → incidents(id) ON DELETE CASCADE` — escalations are
  tied to the incident's lifetime; a deleted incident takes its
  escalation rows with it.
- `peer_id → peer_csirts(id) ON DELETE RESTRICT` — a peer cannot be
  removed while it has open escalations. Operators must close or
  reassign first.

`UNIQUE (incident_id, peer_id)` — one escalation per (incident,
peer) pair. Re-escalations require either an ack or a new incident.

---

## citadel_outbox

Durable queue for outbound CITADEL events. The Go API writes a row
in the same transaction as the business write, so the outbox is
**exactly consistent** with the business state on commit.

```sql
CREATE TABLE citadel_outbox (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id      text NOT NULL UNIQUE,
    event_type    text NOT NULL,
    payload       jsonb NOT NULL,
    state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sending', 'sent', 'failed')),
    attempts      int NOT NULL DEFAULT 0,
    last_error    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    sent_at       timestamptz,
    target_type   text NOT NULL,
    target_id     uuid
);

CREATE INDEX idx_citadel_outbox_state_created ON citadel_outbox(state, created_at);
```

`event_id` is the CITADEL-side idempotency key. `event_type` is one
of the four constants in [`internal/citadel/events.go`](../internal/citadel/events.go).
`target_type` / `target_id` denote the business row this event is
about (`incident` / `advisory` / `escalation`) so operators can
join from the outbox back to the source-of-truth row.

### CITADEL outbox state machine

```
                 Insert (txn-coupled)
                       │
                       ▼
                  ┌─────────┐
                  │ pending │
                  └────┬────┘
                       │ watcher: UPDATE … SET state='sending' WHERE state='pending'
                       │ FOR UPDATE SKIP LOCKED
                       ▼
                  ┌─────────┐
                  │ sending │
                  └─┬─────┬─┘
       2xx          │     │ network / 5xx / signature reject
       from CITADEL │     │ attempts++, last_error set
                    ▼     ▼
               ┌──────┐ ┌─────────┐
               │ sent │ │ pending │ (retried on next tick)
               └──────┘ └────┬────┘
                             │ retry budget exhausted
                             ▼
                        ┌────────┐
                        │ failed │ (terminal — audited out of band)
                        └────────┘
```

Transitions:

- `pending → sending`: watcher claims the row with `FOR UPDATE SKIP
  LOCKED` so multiple API replicas cooperate without a leader.
- `sending → sent`: HTTP 2xx from CITADEL. `sent_at = now()`.
- `sending → pending`: any non-2xx or transport error. `attempts++`,
  `last_error` recorded, row eligible again on the next tick.
- `pending → failed`: retry budget exhausted (see
  [performance.md](performance.md) for the budget). Operators audit
  failed rows manually; they are never auto-retried.

`OPENCSIRT_OUTBOX_TICK` (default `10s`) controls the watcher poll
cadence.

---

## audit_log

Read-side and non-CITADEL audit trail. CITADEL handles privileged
write actions (incident open/close, advisory publish, escalation);
this table captures everything else (login, listing, viewing,
config reads) so a forensic timeline is reconstructable without
external CITADEL access.

```sql
CREATE TABLE audit_log (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id      uuid,
    actor_role    text,
    action        text NOT NULL,
    target_type   text,
    target_id     uuid,
    metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_actor   ON audit_log(actor_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);
```

`actor_id` is nullable because some events (e.g. anonymous health
check, IRFlow webhook) have no JWT subject. `actor_role` is
captured at write time so a later role change does not retroact-
ively rewrite history.

---

## ioc_ingest_log

Audit trail for ThreatFlow IOC bundle pulls. Same pattern as the
matching table in OpenScrub.

```sql
CREATE TABLE ioc_ingest_log (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    source          text NOT NULL,
    bundle_sha256   text NOT NULL,
    count           int NOT NULL,
    ingested_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_ioc_ingest_log_source_ingested ON ioc_ingest_log(source, ingested_at DESC);
```

The puller deduplicates by `bundle_sha256` so re-pulling an
already-ingested bundle is cheap and idempotent.

---

## ON DELETE semantics summary

| FK | Behaviour | Rationale |
|---|---|---|
| `incidents.constituency_id → constituencies` | `SET NULL` | Preserve incident history when retiring constituencies. |
| `advisories.incident_id → incidents` | `SET NULL` | Preserve published CSAF documents when redacting incidents. |
| `escalations.incident_id → incidents` | `CASCADE` | Escalation has no meaning without its incident. |
| `escalations.peer_id → peer_csirts` | `RESTRICT` | Prevent silent removal of a peer with open escalations. |

The two `SET NULL` paths are the evidence-preservation paths — they
mirror the `mitigations.rule_id` decision in
[OpenScrub data-model.md](../../openscrub/docs/data-model.md). The
`CASCADE` and `RESTRICT` paths protect referential integrity for
operational rows.

---

## See also

- [migrations.md](migrations.md)
- [api.md](api.md)
- [architecture.md](architecture.md)
- [performance.md](performance.md)
