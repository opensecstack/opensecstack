# SecureLab REST API

> **Version:** v1.0.0 (Go, `cmd/server`, `internal/api`)
>
> `GET /health` is unauthenticated. Every other endpoint requires a
> valid bearer token and passes through RBAC role checks (see
> `internal/api/server.go`).

## Base URL

```
http://<host>:8080/api/v1
```

(`/health` itself is not under `/api/v1` — see below.)

## Authentication

Requests carry a JWT bearer token:

```
Authorization: Bearer <token>
```

Tokens are validated either as HS256 against `SECURELAB_JWT_SECRET`
or, when `SECURELAB_SINAUTH_URL` is configured, as RS256 SSO tokens
against the sinauth JWKS endpoint (`internal/api/middleware`). There
is no local `/auth/login` endpoint in this service — authentication is
delegated to sinauth.

### Roles

Routes are gated with `middleware.RequireRole(role)`, where role is
one of `analyst`, `operator`, or `admin` (higher roles satisfy lower
requirements):

| Endpoint | Method | Min. role |
|---|---|---|
| `/health` | GET | — (no auth) |
| `/api/v1/scenarios` | GET | analyst |
| `/api/v1/scenarios/{id}` | GET | analyst |
| `/api/v1/scenarios` | POST | operator |
| `/api/v1/scenarios/{id}/run` | POST | operator |
| `/api/v1/runs` | GET | analyst |
| `/api/v1/runs/{id}` | GET | analyst |
| `/api/v1/environments` | GET | analyst |
| `/api/v1/environments/{id}` | GET | analyst |
| `/api/v1/environments` | POST | admin |
| `/api/v1/environments/{id}` | DELETE | admin |
| `/api/v1/coverage` | GET | analyst |

There is no `PUT`/`DELETE` on scenarios, no standalone `/executions`
resource, no `/attack-library` endpoint, and no
`/coverage/{technique_id}` or ATT&CK Navigator layer export in the
current implementation.

## Response shape

Handlers write plain JSON directly (no `{"data": ..., "meta": ...}`
envelope). List endpoints return a bare JSON array (`[]` when empty,
never `null`); single-resource endpoints return the resource object
directly. Errors from `http.Error` are a plain text body with the
corresponding HTTP status code — there is no structured
`{"error": ..., "detail": ...}` error envelope.

---

## Health

### `GET /health`

Liveness check. Pings the database with a 2-second timeout on every
call.

**Response 200:**
```json
{
  "status": "ok",
  "db": true,
  "uptime_seconds": 812,
  "version": "1.0.0"
}
```

**Response 503** with `"status": "degraded", "db": false` when the
database is unreachable.

---

## Scenarios

### `GET /api/v1/scenarios`

Returns all scenario rows as a JSON array.

**Response 200:**
```json
[
  {
    "id": "01HX...",
    "name": "bola-basic",
    "description": "BOLA via sequential integer ID enumeration",
    "mitre_technique_ids": ["T1078"],
    "tags": ["api", "owasp-a1", "bola"],
    "severity": "high",
    "timeout_seconds": 180,
    "yaml_content": "name: bola-basic\n...",
    "created_at": "2026-01-15T09:00:00Z",
    "updated_at": "2026-01-15T09:00:00Z"
  }
]
```

### `GET /api/v1/scenarios/{id}`

Returns 404 (plain text) if the scenario does not exist. Response
shape is a single scenario object as above.

### `POST /api/v1/scenarios` (operator+)

**Request body:**
```json
{
  "name": "bola-basic",
  "description": "BOLA via sequential integer ID enumeration",
  "mitre_technique_ids": ["T1078"],
  "tags": ["api", "owasp-a1", "bola"],
  "severity": "high",
  "timeout_seconds": 180,
  "yaml_content": "<scenario YAML as string>"
}
```

The YAML is parsed and validated (`internal/scenarios.LoadFromYAML` +
`Validate`) before the row is inserted; see
[docs/scenario-spec.md](scenario-spec.md) for the YAML format.

**Response 201:** `{"id": "<new-scenario-id>"}`
**Response 422:** validation failure (plain text body).

### `POST /api/v1/scenarios/{id}/run` (operator+)

**Request body:**
```json
{
  "environment_id": "env_test_01"
}
```

Looks up the scenario and environment, requires the environment to be
in `ready` status, validates the scenario against the environment,
inserts a `scenario_runs` row (`status: pending`), and hands it to the
scheduler.

**Response 202:** `{"run_id": "<new-run-id>"}`
**Response 404:** scenario or environment not found.
**Response 409:** environment is not in `ready` state.
**Response 422:** scenario/environment validation failure.

---

## Runs

### `GET /api/v1/runs`

Returns all `scenario_runs` rows as a JSON array.

**Response 200:**
```json
[
  {
    "id": "01HY...",
    "scenario_id": "01HX...",
    "environment_id": "env_test_01",
    "status": "completed",
    "started_at": "2026-01-15T09:05:00Z",
    "finished_at": "2026-01-15T09:06:00Z",
    "attack_events": [ /* raw JSON */ ],
    "detection_events": [ /* raw JSON */ ],
    "detection_latency_ms": 4200,
    "detected": true,
    "notes": ""
  }
]
```

### `GET /api/v1/runs/{id}`

Returns a single run object as above, or 404.

---

## Environments

### `GET /api/v1/environments` / `GET /api/v1/environments/{id}`

Returns environment rows:

```json
{
  "id": "env_test_01",
  "name": "isolated-owasp-lab",
  "kind": "docker",
  "target_url": "http://target-api:9090",
  "network_id": "securelab-test-net",
  "status": "ready",
  "created_at": "2026-01-15T09:00:00Z",
  "updated_at": "2026-01-15T09:00:00Z"
}
```

### `POST /api/v1/environments` (admin only)

**Request body:**
```json
{
  "name": "isolated-owasp-lab",
  "kind": "docker",
  "target_url": "http://target-api:9090",
  "network_id": "securelab-test-net"
}
```

### `DELETE /api/v1/environments/{id}` (admin only)

---

## MITRE ATT&CK Coverage

### `GET /api/v1/coverage`

Returns the `mitre_coverage` table snapshot wrapped in an `entries`
key:

```json
{
  "entries": [
    {
      "technique_id": "T1059.001",
      "technique_name": "Command and Scripting Interpreter: PowerShell",
      "tactic": "execution",
      "scenario_count": 2,
      "last_detected_at": "2026-01-15T09:06:00Z",
      "detection_rate": 87.5
    }
  ]
}
```

See [docs/mitre-attack-coverage.md](mitre-attack-coverage.md).

---

## Related

- [docs/scenario-spec.md](scenario-spec.md) — YAML scenario format
- [docs/configuration.md](configuration.md) — env vars
- [docs/architecture.md](architecture.md) — component overview
