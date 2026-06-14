# OpenCSIRT Architecture

> Status: v1.0.0. Phase 3 of the [opensecstack](../../README.md)
> ecosystem. National / sector CSIRT operations platform. Companion
> to [data-model.md](data-model.md), [api.md](api.md), and
> [deployment.md](deployment.md).

OpenCSIRT is a federated incident-response and advisory-publication
platform for national and sector CSIRTs. It accepts incident
reports (from operators, abuse mailboxes, or
[IRFlow](../../irflow/README.md) webhooks), pulls IOCs from
[ThreatFlow](../../threatflow/README.md), drafts CSAF 2.0 advisories
through a Python subsystem, and emits durable evidence to
[CITADEL](../../citadel/README.md). It interoperates with peer
CSIRTs via the [handshake protocol](peer-csirt-handshake-protocol.md)
and pushes Article 23 notifications to the
[NIS2 Compass](../../nis2compass/README.md) regulator-facing surface.

---

## Top-level component diagram

```
                       ┌─────────────────────────┐
                       │   Operator browser      │
                       │   React dashboard       │
                       └────────────┬────────────┘
                                    │ HTTPS
                                    ▼
                       ┌─────────────────────────┐
                       │    OpenCSIRT API        │   Go 1.22+ (chi)
                       │    :8088                │   stateless replicas
                       └─┬──────┬─────────────┬──┘
                         │      │             │
        ┌────────────────┘      │             └─────────────────┐
        │                       │                               │
        ▼                       ▼                               ▼
┌────────────────┐   ┌────────────────────┐         ┌──────────────────────┐
│ PostgreSQL 16  │   │ Advisory subsystem │         │ CITADEL outbox       │
│ constituencies │   │ Python :8089       │         │ watcher (in-process) │
│ incidents      │   │ CSAF gen, IOC      │         │ pending → sending    │
│ advisories     │   │ enrichment, YARA,  │         │ → sent | failed      │
│ peer_csirts    │   │ ML triage          │         │ HMAC-SHA256 to       │
│ citadel_outbox │   │                    │         │ CITADEL /events      │
│ audit_log      │   └────────────────────┘         └──────────────────────┘
│ ioc_ingest_log │
└────────────────┘
```

The Go API is the public-facing control plane. It owns Postgres,
mints JWTs, enforces role-based access, and writes the CITADEL
outbox. The Python advisory subsystem is internal — only the API
calls it (over `OPENCSIRT_ADVISORY_SERVICE_URL`, default
`http://localhost:8089`) with a service JWT.

The CITADEL outbox watcher is a goroutine inside the API process.
It polls the [`citadel_outbox`](data-model.md#citadel_outbox)
table on `OPENCSIRT_OUTBOX_TICK` cadence (default `10s`) and emits
the four event types declared in
[`internal/citadel/events.go`](../internal/citadel/events.go):

- `opencsirt.incident_opened`
- `opencsirt.incident_closed`
- `opencsirt.advisory_published`
- `opencsirt.escalation_sent`

---

## Inter-platform integration

```
┌────────────┐  IOC pull (60s default)              ┌──────────────┐
│ ThreatFlow │ ◀──────────────────────────────────▶ │              │
│  feeds     │  advisory push (CSAF on publish)     │              │
└────────────┘                                       │              │
                                                     │              │
┌────────────┐  POST /integrations/irflow/incident   │  OpenCSIRT   │
│  IRFlow    │ ───────────────────────────────────▶  │   :8088      │
│            │  HMAC-SHA256 verified                 │              │
└────────────┘                                       │              │
                                                     │              │
┌──────────────┐  Article 23 notify on publish       │              │
│ NIS2 Compass │ ◀─────────────────────────────────  │              │
└──────────────┘                                     │              │
                                                     │              │
┌────────────┐  cross-CSIRT AI threat intel          │              │
│ VertGuard  │ ◀──────────────────────────────────▶  │              │
└────────────┘                                       └──────┬───────┘
                                                            │
                                  CITADEL evidence (HMAC) ──┘
```

Wiring details, retry contracts, and HMAC envelopes live in the
per-integration documents:

- [threatflow-integration.md](threatflow-integration.md)
- [irflow-integration.md](irflow-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [vertguard-integration.md](vertguard-integration.md)
- [citadel-integration.md](citadel-integration.md)

---

## Incident-to-advisory data lifecycle

```
   incident open ──▶ triage ──▶ advisory draft ──▶ publish
        │              │              │               │
        ▼              ▼              ▼               ▼
   citadel_outbox  audit_log    advisories.state   citadel_outbox
   incident_       (read-side  = 'draft'           advisory_
   opened          forensic                        published
                   trail)                          + ThreatFlow push
                                                   + NIS2 notify (if
                                                     scoped to NIS2
                                                     constituency)
```

1. Incident lands via `POST /api/v1/incidents`, IRFlow webhook, or
   peer CSIRT escalation. Row inserted in
   [`incidents`](data-model.md#incidents).
2. Operator triages — status moves `open → triaged → contained →
   closed`. Each transition writes an `audit_log` row.
3. CSIRT lead drafts an advisory: `POST /api/v1/advisories`. The
   API forwards the draft request to the Python subsystem, which
   generates the CSAF 2.0 JSON, runs IOC enrichment (VirusTotal,
   OTX), and returns the sealed document.
4. `POST /api/v1/advisories/{id}/publish` flips state to
   `published`, writes `published_at` / `published_by`, enqueues
   the CITADEL `advisory_published` event, and triggers the
   ThreatFlow push and NIS2 notification side-effects.
5. The CITADEL outbox watcher emits both the `incident_opened` and
   `advisory_published` events to CITADEL on its next tick.

---

## Authorization matrix (6 roles)

Roles are declared in
[`internal/auth/auth.go`](../internal/auth/auth.go). Rank ordering
(higher = more access) drives the `RequireRole` middleware:

| Role | Rank | Read incidents | Write incidents | Draft advisory | Publish advisory | Escalate to peer | Admin |
|---|---|---|---|---|---|---|---|
| `viewer` | 1 | yes | no | no | no | no | no |
| `external_peer` | 2 | TLP:CLEAR/GREEN advisories only | submit IOC bundles | no | no | no | no |
| `analyst` | 3 | yes | yes | yes (draft) | no | no | no |
| `operator` | 4 | yes | yes | yes | no | no | no |
| `csirt_lead` | 5 | yes | yes | yes | yes | yes | no |
| `admin` | 6 | yes | yes | yes | yes | yes | yes |

`csirt_lead` is the lowest role authorised to publish advisories
and to send escalations to peer CSIRTs. `external_peer` is a
deliberately narrow role for federated trust — see
[peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md).

---

## CITADEL outbox state machine

Every CITADEL event is durable. The API writes to
[`citadel_outbox`](data-model.md#citadel_outbox) inside the same
transaction that writes the business row (incident, advisory,
escalation), so the outbox row and the business state are consistent
on commit.

```
                 Insert (txn-coupled)
                       │
                       ▼
                  ┌─────────┐
        watcher   │ pending │
        picks up  └────┬────┘
                       │ UPDATE … SET state='sending'
                       ▼
                  ┌─────────┐
                  │ sending │
                  └─┬─────┬─┘
       2xx from     │     │  network / 5xx / signature reject
       CITADEL      │     │  attempts++, last_error set
                    ▼     ▼
               ┌──────┐ ┌─────────┐
               │ sent │ │ pending │ (retried on next tick)
               └──────┘ └────┬────┘
                             │ retry budget exhausted
                             ▼
                        ┌────────┐
                        │ failed │ (terminal, audit only)
                        └────────┘
```

Wire envelope (mirrors CyberPath / IRFlow / OpenScrub):

```
POST {OPENCSIRT_CITADEL_API_URL}/api/v1/events
X-Event-Type:   opencsirt.<event_type>
X-Key-ID:       OPENCSIRT_CITADEL_KEY_ID
X-Timestamp:    RFC3339 UTC
X-Signature:    hex(HMAC-SHA256(secret, timestamp || "." || body))
Content-Type:   application/json
```

Replay window is enforced server-side by CITADEL (±5 min). The
watcher only transitions `sending → sent` on confirmed 2xx;
partial failures stay `pending` and re-enter the queue.

`OPENCSIRT_CITADEL_DRY_RUN=true` (default) builds and signs the
event but does not POST it — useful for first-deploy smoke tests.

---

## Why two languages

The Go API and the Python advisory subsystem are intentionally
separated processes communicating over loopback HTTP.

**Go for the API and orchestration plane** because:

- Stateless, low-latency request handling (chi router, `pgxpool`
  pooling, `OPENCSIRT_DB_MAX_CONNS=16` default).
- HMAC-SHA256, JWT (HS256) and Postgres drivers are first-class
  in the standard library and `golang-jwt/jwt/v5`.
- The CITADEL outbox watcher, ThreatFlow puller, and IRFlow webhook
  receiver share the same supervision tree and shutdown semantics.
- One binary, container-native, easy to run as a non-root distroless
  image with all caps dropped.

**Python for advisory generation** because:

- CSAF 2.0 has maintained Python tooling
  ([`csaf-tools`](https://github.com/csaf-tools)) and the schema
  validation libraries live in the Python ecosystem.
- IOC enrichment connectors (VirusTotal, AlienVault OTX,
  abuse.ch URLhaus, MISP) ship Python SDKs first.
- YARA bindings (`yara-python`) and ML triage classifiers
  (scikit-learn, sentence-transformers) are mature in Python and
  awkward to call from Go.
- Operators write CSAF customisation hooks in Python; we expose
  those as a thin plugin contract in the advisory subsystem
  rather than embedding a JS / Lua engine in Go.

The split is a **process boundary, not a service mesh**. The
Python service binds `127.0.0.1:8089` by default and authenticates
the Go caller with `OPENCSIRT_ADVISORY_SERVICE_JWT`. Operators who
want the two on separate hosts simply override
`OPENCSIRT_ADVISORY_SERVICE_URL`.

---

## Process model

| Process | Replicas | Listen | Privileges |
|---|---|---|---|
| `opencsirt-api` (Go) | N (stateless) | HTTP `:8088` | non-root, all caps dropped |
| `opencsirt-advisory` (Python) | 1 (v1.0.0) | HTTP `:8089` | non-root, no caps |
| `opencsirt-web` (React via nginx) | M | HTTP `:80` | non-root |
| `postgres:16` | 1 (StatefulSet / volume) | TCP `5432` cluster-internal | – |

See [deployment.md](deployment.md) for the Helm topology and
NetworkPolicy. v1.0.0 does **not** horizontally scale the Python
advisory subsystem — single-instance latency budget covered in
[performance.md](performance.md).

---

## Failure modes

- **API down**: incidents and advisories cannot be written.
  CITADEL emission freezes. ThreatFlow pull pauses. Recovery is
  fast — the outbox catches up on restart.
- **Python advisory down**: incident triage continues. `POST
  /api/v1/advisories` returns `503`. Already-drafted advisories
  can still be published (publish does not call the Python
  service — only drafting does).
- **Postgres down**: API returns `503` on writes. Reads degrade.
  The outbox watcher pauses; events queued in process memory are
  lost if the API crashes before commit (this is why writes are
  txn-coupled, not in-memory).
- **CITADEL down / unreachable**: outbox rows accumulate in
  `pending`. No data loss. Operators see the backlog via
  `/api/v1/metrics/snapshot`.
- **ThreatFlow down**: IOC pull staleness alert; existing IOCs
  continue to inform triage. No automatic withdrawal.

---

## See also

- [data-model.md](data-model.md) — full schema
- [api.md](api.md) — endpoint reference
- [configuration.md](configuration.md) — env var table
- [deployment.md](deployment.md) — Helm + Compose topology
- [performance.md](performance.md) — headline targets
- [advisory-authoring-guide.md](advisory-authoring-guide.md) — operator guide
- [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md) — federated trust
