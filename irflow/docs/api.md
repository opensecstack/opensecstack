# IRFlow API Reference

IRFlow exposes a REST API under `/api/v1`. Default listen address: `:8083`.

- All `/api/v1/*` routes require a `Authorization: Bearer <JWT>` header
  unless the table below says otherwise.
- Webhooks (`/api/v1/webhooks/*`) use HMAC-SHA256 signatures instead of
  JWT (see [Webhooks](#webhooks)).
- Responses are always JSON (`Content-Type: application/json`).

## Authentication

### JWT (API)

IRFlow verifies HS256 JWTs signed with `IRFLOW_AUTH_SECRET`. The token's
`role` claim determines what the caller can do (see RBAC matrix below).

Expected claims:

```json
{
  "sub":   "user-id",
  "role":  "admin|operator|verifier|viewer|service",
  "email": "optional@example.com",
  "iss":   "irflow",
  "iat":   1712580000,
  "exp":   1712608800
}
```

Dev-only: `irflow auth issue --user alice --role operator --ttl 1h`
produces a signed token using the same secret.

### HMAC (Webhooks)

```
signed_payload = <unix_timestamp>.<raw_body>
signature       = hex(HMAC-SHA256(webhook_secret, signed_payload))

Headers:
  X-Irflow-Signature: sha256=<signature>
  X-Irflow-Timestamp: <unix_timestamp>
```

Timestamps outside ±5 min (configurable) are rejected with 401.

### RBAC matrix

| Role | Read `/api/v1/*` | Write (POST/PATCH) | Delete |
|---|---|---|---|
| admin | ✓ | ✓ | ✓ |
| operator | ✓ | ✓ | — |
| service | ✓ | ✓ | — |
| verifier | ✓ | — | — |
| viewer | ✓ | — | — |

## Endpoints

### Health

```
GET /health
```

Returns `{"status":"ok"}` always. Used by load balancers for liveness.

```
GET /health/detail
```

Liveness + DB ping + build metadata. Returns 200 or 503.

```json
{
  "status":  "ok",
  "version": "1.0.0",
  "commit":  "abc1234",
  "built":   "2026-04-08T10:30:00Z",
  "db":      "ok"
}
```

### Metrics

```
GET /metrics
```

Prometheus text format. See the [metrics catalogue](#metrics-catalogue).

### Incidents

#### List

```
GET /api/v1/incidents?page=1&per_page=20&status=open&severity=P1&source=apiguard
```

Response:

```json
{
  "data": [ { /* Incident */ } ],
  "page": 1,
  "per_page": 20,
  "total_count": 42
}
```

#### Create

```
POST /api/v1/incidents
{
  "title": "Critical API vulnerability",
  "description": "...",
  "severity": "P1",
  "source": "manual",
  "source_ref": "",
  "project_id": "proj-a",
  "commander_id": "alice",
  "lead_id": "bob"
}
```

Returns 201 with the full `Incident` including auto-populated
`nis2_notify_required` (true for P1/P2/P3).

#### Get / Patch / Delete

```
GET    /api/v1/incidents/{id}
PATCH  /api/v1/incidents/{id}   # partial fields; status transitions are guarded
DELETE /api/v1/incidents/{id}   # admin only
```

Valid status transitions:

```
open          → investigating | closed
investigating → contained | closed
contained     → eradicating | closed
eradicating   → recovering | closed
recovering    → closed
closed        → (terminal)
```

Invalid transitions return `400 {"error":"invalid status transition"}`.

#### Actions (MARSHAL-governed)

```
POST /api/v1/incidents/{id}/actions
{
  "action_type":  "contain|escalate|recover|close",
  "operator_id":  "alice",
  "verifier_id":  "bob",
  "description":  "block endpoint",
  "evidence":     { "any": "json" }
}
```

Behaviour:

- Separation of Duties enforced (400 if `operator_id == verifier_id`).
- If CITADEL MARSHAL is configured, the action is evaluated:
  - `EXECUTE` → 201 Created, action stored with `marshal_decision` +
    `worm_entry_id`.
  - `REFUSE` → 403, action **not** stored, error message includes
    CITADEL's reasons.
  - `HARD_STOP` → 403, action **not** stored.
- If MARSHAL is not configured, action is stored locally with
  `marshal_decision` empty.

```
GET /api/v1/incidents/{id}/actions
```

Returns all actions plus related timeline entries.

#### IOCs

```
POST /api/v1/incidents/{id}/iocs
{
  "ioc_type":   "ip|domain|hash|url",
  "ioc_value":  "198.51.100.7",
  "confidence": 0.85,
  "source":     "threatflow",
  "stix_bundle": { }
}

GET /api/v1/incidents/{id}/iocs
```

#### Timeline

```
GET /api/v1/incidents/{id}/timeline
```

Chronological, append-only.

### Playbooks

#### CRUD

```
GET    /api/v1/playbooks?page=1&per_page=50&status=active
POST   /api/v1/playbooks
GET    /api/v1/playbooks/{id}
PATCH  /api/v1/playbooks/{id}
DELETE /api/v1/playbooks/{id}   # admin only
```

Create payload:

```json
{
  "name":        "Critical Finding Response",
  "description": "...",
  "version":     "1.0",
  "status":      "active",
  "trigger":     { "event_type": "apiguard.finding.critical", "severity": "P1" },
  "steps": [
    { "id": "a", "name": "create", "type": "action", "on_success": "b" },
    { "id": "b", "name": "notify", "type": "notify" }
  ],
  "created_by": "ops"
}
```

Step types: `action`, `notify`, `wait`, `enrich`, `scan`, `conditional`.

#### Execute

```
POST /api/v1/playbooks/{id}/execute
{ "incident_id": "inc-1234" }
```

Returns 202 Accepted with the newly-created `Execution` in `pending`
state. The executor runs asynchronously with a 1-hour deadline. Poll
`/api/v1/executions/{id}` for status (`pending → running → completed |
failed | cancelled`).

#### Execution inspection

```
GET /api/v1/playbooks/{id}/executions
GET /api/v1/executions/{id}
```

### Webhooks

All three endpoints:

- Require the HMAC headers described above.
- Reject oversized bodies (default 1 MiB) with 413.
- Fail closed (503) when the corresponding secret is not configured.

```
POST /api/v1/webhooks/apiguard
```

APIGuard finding → incident mapping:

| `finding.severity` | Result |
|---|---|
| `critical` | 201 Created, P1 incident with `source=apiguard`, `source_ref=scan_id` |
| `high` | 201 Created, P2 incident |
| `medium` / `low` / `informational` | 202 Accepted, no incident created |

```
POST /api/v1/webhooks/citadel
```

| `event_type` | Result |
|---|---|
| `hard_stop` | 201 Created, P1 incident with `source=citadel` |
| `marshal_denied`, `worm_tamper`, etc. | 202 Accepted, logged only |

```
POST /api/v1/webhooks/threatflow
```

| Payload shape | Result |
|---|---|
| `incident_id` set | 200 OK, all IOCs attached to the named incident |
| `incident_id` empty | 202 Accepted, queued for future correlation |

### Stats

```
GET /api/v1/stats
```

Response:

```json
{
  "total": 42,
  "by_severity": { "P1": 3, "P2": 8, "P3": 19, "P4": 12 },
  "by_status":   { "open": 7, "investigating": 5, "contained": 9, "eradicating": 2, "recovering": 3, "closed": 16 },
  "by_source":   { "apiguard": 22, "citadel": 5, "threatflow": 8, "manual": 7 }
}
```

## Metrics catalogue

Exposed at `GET /metrics`. Namespace: `irflow_`.

| Metric | Type | Labels |
|---|---|---|
| `irflow_http_requests_total` | counter | method, route, status |
| `irflow_http_request_duration_seconds` | histogram | method, route |
| `irflow_http_requests_in_flight` | gauge | "all" |
| `irflow_incidents_created_total` | counter | severity, source |
| `irflow_actions_submitted_total` | counter | outcome (EXECUTE / REFUSE / HARD_STOP / LOCAL) |
| `irflow_playbook_executions_total` | counter | outcome |
| `irflow_playbook_steps_total` | counter | step_type, result |
| `irflow_webhooks_received_total` | counter | source, result |
| `irflow_governance_calls_total` | counter | target, result |
| `irflow_db_pool_connections` | gauge | state (acquired / idle / max) |

Plus the standard Go runtime + process collectors (`go_*`, `process_*`).

## Error format

Every failure response uses:

```json
{ "error": "human-readable message" }
```

| HTTP | When |
|---|---|
| 400 | Malformed JSON, invalid status transition, SoD violation, missing webhook headers |
| 401 | Missing / invalid / expired JWT; bad webhook signature; stale webhook timestamp |
| 403 | RBAC rejection; MARSHAL `REFUSE` or `HARD_STOP` |
| 404 | Unknown ID |
| 413 | Webhook body exceeds `IRFLOW_WEBHOOK_MAX_BODY_SIZE` |
| 500 | Unexpected internal failure — always logged with correlation `request_id` |
| 503 | Webhook secret not configured; DB unreachable on `/health/detail` |
