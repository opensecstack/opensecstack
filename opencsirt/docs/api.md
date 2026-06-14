# OpenCSIRT API

> v1.0.0 · port `8088` · prefix `/api/v1`. Machine-readable contract:
> [`api/openapi.yaml`](../api/openapi.yaml). If this page disagrees
> with the OpenAPI, the OpenAPI wins.

OpenCSIRT exposes a single HTTP API on `OPENCSIRT_HTTP_ADDR`
(default `:8088`). All non-public endpoints require a Bearer JWT;
the role hierarchy enforced by `RequireRole` is documented in
[architecture.md](architecture.md#authorization-matrix-6-roles).

The 16 endpoints group into 7 resource families.

---

## Auth

### `POST /api/v1/auth/login` — public

Issues a JWT for an entry in `OPENCSIRT_USERS`.

```json
{ "username": "lead", "password": "<password>" }
```

Response:

```json
{
  "token": "eyJhbGciOi…",
  "role": "csirt_lead",
  "sub": "1f3a0c12-…-…-…",
  "expires_at": "2026-05-09T22:11:30Z"
}
```

- `401 Invalid credentials` — username unknown or hash mismatch.
- `503 Issuer disabled` — `OPENCSIRT_USERS` empty.

---

## Health

### `GET /api/v1/health` — public

Liveness + dependency status. No auth.

```json
{
  "status": "ok",
  "db": true,
  "advisory_service": true,
  "uptime_seconds": 1284
}
```

`advisory_service` reflects a recent ping of
`OPENCSIRT_ADVISORY_SERVICE_URL`. `db` is `true` after a successful
`SELECT 1` round-trip.

---

## Constituencies

Resource: organisations the CSIRT serves. Schema in
[data-model.md](data-model.md#constituencies).

### `GET /api/v1/constituencies` — `analyst`+

Query: `limit`, `offset`. Returns:

```json
{ "constituencies": [ { "id": "…", "name": "…", "sector": "energy", "country": "AL", "nis2_status": "essential", "primary_contact_email": "soc@…" } ], "count": 12 }
```

### `POST /api/v1/constituencies` — `operator`+

Body matches the `Constituency` schema. `country` is ISO 3166-1
alpha-2. `nis2_status` ∈ `essential | important | out_of_scope`.
Returns `201` with the inserted row.

### `GET /api/v1/constituencies/{id}` — `analyst`+

Returns the constituency or `404`.

### `PUT /api/v1/constituencies/{id}` — `operator`+

Updates the row. `id` in the path wins over `id` in the body.

---

## Incidents

Resource: per-constituency incidents. Schema in
[data-model.md](data-model.md#incidents).

### `GET /api/v1/incidents` — `analyst`+

Query: `status`, `severity`, `limit`, `offset`. Returns:

```json
{
  "incidents": [
    {
      "id": "…",
      "constituency_id": "…",
      "source": "irflow",
      "severity": "high",
      "status": "triaged",
      "title": "Ransomware indicators on energy provider",
      "description": "…",
      "opened_at": "2026-05-09T08:14:02Z",
      "closed_at": null,
      "citadel_emitted": true,
      "metadata": {}
    }
  ],
  "count": 47
}
```

### `POST /api/v1/incidents` — `operator`+

Body matches `Incident`. `source` ∈ `irflow | manual | abuse_mailbox
| peer_csirt`. `severity` ∈ `low | medium | high | critical`.
`status` defaults to `open`. Returns `201`.

The handler enqueues an `opencsirt.incident_opened` row in
`citadel_outbox` inside the same transaction.

### `GET /api/v1/incidents/{id}` — `analyst`+

Returns the full incident or `404`.

### `POST /api/v1/incidents/{id}/close` — `operator`+

Sets `status='closed'`, `closed_at=now()`, enqueues
`opencsirt.incident_closed`. `200` on success.

### `POST /api/v1/incidents/{id}/escalate` — `operator`+

Marks the incident as triaged and emits an `opencsirt.escalation_sent`
CITADEL event. Use when the incident requires cross-CSIRT notification
or is being handed to a peer CSIRT.

`200` on success, returns the updated `Incident`. `403` if caller lacks
`operator` role. `404` if incident not found.

---

## Advisories

Resource: CSAF 2.0 advisories. Schema in
[data-model.md](data-model.md#advisories). Authoring guide:
[advisory-authoring-guide.md](advisory-authoring-guide.md).

### `GET /api/v1/advisories` — `analyst`+

Query: `state` (`draft | published | withdrawn`), `tlp` (`CLEAR |
GREEN | AMBER | RED`), `limit`, `offset`.

> **Note:** Automatic filtering of results to `state='published' AND
> tlp IN ('CLEAR','GREEN')` for `external_peer` callers is not yet
> implemented — planned for v1.1. Currently the handler applies only
> the caller-supplied `state` and `tlp` query parameters with no
> role-based enforcement at the API layer.

```json
{
  "advisories": [
    {
      "id": "…",
      "incident_id": "…",
      "csaf_id": "OPENCSIRT-2026-0042",
      "csaf_version": "2.0",
      "state": "published",
      "tlp": "GREEN",
      "title": "Active exploitation of CVE-2026-12345",
      "summary": "…",
      "published_at": "2026-05-09T11:02:00Z",
      "published_by": "…",
      "citadel_emitted": true,
      "created_at": "2026-05-09T10:48:11Z",
      "updated_at": "2026-05-09T11:02:00Z"
    }
  ],
  "count": 137
}
```

### `POST /api/v1/advisories` — `analyst`+

Drafts a CSAF 2.0 document. The Go API forwards the request to the
Python advisory subsystem (`OPENCSIRT_ADVISORY_SERVICE_URL`) which
generates the full `csaf_doc`, runs IOC enrichment, and returns the
sealed JSON. The API persists `state='draft'`. Returns `201`.

```json
{
  "incident_id": "…",
  "title": "Active exploitation of CVE-2026-12345",
  "tlp": "GREEN",
  "summary": "…"
}
```

### `GET /api/v1/advisories/{id}` — `analyst`+

Returns the full advisory including the `csaf_doc` JSON.

### `POST /api/v1/advisories/{id}/publish` — `csirt_lead`+

Seals the advisory: `state='published'`, `published_at=now()`,
`published_by=<jwt sub>`. Side effects:

- Enqueue `opencsirt.advisory_published` in `citadel_outbox`.
- Push CSAF JSON to ThreatFlow if configured.
- Push Article 23 notification to NIS2 Compass if the linked
  incident has severity `high` or `critical`.

`200` on success. Idempotent — re-publishing a published advisory
is a no-op.

### `POST /api/v1/advisories/{id}/withdraw` — `csirt_lead`+

Marks the advisory withdrawn: `state='withdrawn'`. Use when a
published advisory is superseded or needs to be rescinded. Do not
edit the CSAF document in place — issue a new advisory and cross-
reference the withdrawn one.

`200` on success. Returns the updated advisory. No-op if already
withdrawn. Error `409` if the advisory is still in `draft` state.

---

## Metrics

### `GET /api/v1/metrics` — `analyst`+

Prometheus exposition (`text/plain; version=0.0.4`). JWT-gated;
provision a long-lived analyst JWT for the scraper. See
[deployment.md](deployment.md) for Prometheus wiring.

### `GET /api/v1/metrics/snapshot` — `analyst`+

JSON snapshot for the React dashboard. Shape:

```json
{
  "incidents_by_status": { "open": 12, "triaged": 5, "contained": 3, "closed": 47 },
  "advisories_by_state": { "draft": 2, "published": 17, "withdrawn": 3 },
  "outbox_pending": 0,
  "outbox_failed": 0,
  "citadel_queue_depth": 0,
  "iocs_last_ingested_at": "2026-05-09T11:14:00Z",
  "iocs_last_bundle_size": 312,
  "advisory_service_up": true,
  "node": "opencsirt-0",
  "version": "1.0.0",
  "snapshot_at": "2026-05-09T11:20:00Z"
}
```

---

## Integrations

### `POST /api/v1/integrations/irflow/incident` — public, HMAC-verified

IRFlow webhook receiver. Headers:

- `X-IRFlow-Timestamp`: RFC3339 UTC
- `X-IRFlow-Signature`: `hex(HMAC-SHA256(OPENCSIRT_IRFLOW_WEBHOOK_SECRET, timestamp || "." || body))`

Body is the IRFlow incident JSON; the handler maps it to an
`incidents` row with `source='irflow'`. `200` on accepted, `401`
on signature mismatch. Empty `OPENCSIRT_IRFLOW_WEBHOOK_SECRET`
rejects all calls. See [irflow-integration.md](irflow-integration.md).

---

## Errors

Errors are `application/json`:

```json
{ "error": "incident not found", "code": 404 }
```

| Code | Meaning |
|---|---|
| `400` | Malformed body / invalid enum / failed schema validation |
| `401` | Missing or invalid JWT, or webhook signature mismatch |
| `403` | JWT valid but role insufficient |
| `404` | Resource not found |
| `409` | Unique constraint violation (e.g. duplicate `csaf_id`) |
| `500` | Server error (logged with request id) |
| `503` | Dependency unavailable (DB, advisory service, issuer disabled) |

---

## See also

- [`api/openapi.yaml`](../api/openapi.yaml) — machine-readable contract
- [data-model.md](data-model.md)
- [architecture.md](architecture.md)
- [advisory-authoring-guide.md](advisory-authoring-guide.md)
