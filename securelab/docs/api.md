# SecureLab REST API

> **Version:** v1.0.0
>
> All endpoints except `/api/v1/health` require authentication.
> Attack library and execution endpoints require operator-level role.
> The full OpenAPI schema is served at `/api/v1/openapi.json` and
> the Swagger UI at `/api/v1/docs` (when `SECURELAB_ENV=development`).

## Base URL

```
http://<host>:8087/api/v1
```

The API is versioned at the path level. Future breaking changes will
use `/api/v2/`.

## Authentication

All non-health endpoints require a bearer token obtained via the
login endpoint. Tokens are scoped to the operator session; TTL is
configurable via `SECURELAB_AUTH_TOKEN_TTL_S` (default: 3600s).

```
Authorization: Bearer <token>
```

| Endpoint | Method | Auth required | Role |
|---|---|:-:|---|
| `/auth/login` | POST | No | — |
| `/health` | GET | No | — |
| All others | — | Yes | operator |

## Standard response shape

**Success (2xx):**
```json
{
  "data": { ... },
  "meta": { "request_id": "01HX..." }
}
```

**Error (4xx / 5xx):**
```json
{
  "error": "error_code",
  "detail": "Human-readable description",
  "request_id": "01HX..."
}
```

---

## Health

### `GET /api/v1/health`

Liveness check. Returns 200 if the API is up, Postgres is reachable,
and Redis is reachable. Returns 503 if any dependency is unhealthy.

**Response 200:**
```json
{
  "status": "ok",
  "db": "ok",
  "redis": "ok",
  "version": "1.0.0"
}
```

---

## Scenarios

### `GET /api/v1/scenarios`

List all scenarios in the library.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tactic` | string | — | Filter by ATT&CK tactic (e.g. `execution`, `persistence`) |
| `technique` | string | — | Filter by ATT&CK technique ID (e.g. `T1059`) |
| `platform` | string | — | Filter by target platform (`windows`, `linux`, `macos`) |
| `page` | int | 1 | Page number |
| `per_page` | int | 50 | Results per page (max 200) |

**Response 200:**
```json
{
  "data": {
    "scenarios": [
      {
        "id": "01HX...",
        "slug": "T1059.001-powershell-exec",
        "title": "PowerShell Command Execution",
        "description": "Executes an encoded PowerShell command via cmd.exe.",
        "mitre_technique": "T1059.001",
        "mitre_sub_technique": "PowerShell",
        "tactic": "execution",
        "platform": ["windows"],
        "version": "1.0.0",
        "step_count": 3,
        "created_at": "2027-10-01T09:00:00Z",
        "updated_at": "2027-10-01T09:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "per_page": 50
  }
}
```

### `GET /api/v1/scenarios/{id}`

Get scenario detail including steps and ATT&CK mapping.

**Path parameters:** `id` — scenario UUID or slug.

**Response 200:**
```json
{
  "data": {
    "id": "01HX...",
    "slug": "T1059.001-powershell-exec",
    "title": "PowerShell Command Execution",
    "description": "...",
    "author": "securelab-core",
    "mitre_technique": "T1059.001",
    "mitre_sub_technique": "PowerShell",
    "tactic": "execution",
    "platform": ["windows"],
    "version": "1.0.0",
    "content_hash": "sha256:abc123...",
    "steps": [
      {
        "index": 1,
        "primitive": "cmd-spawn",
        "description": "Open cmd.exe as unprivileged user",
        "destructive": false,
        "rollback": null
      },
      {
        "index": 2,
        "primitive": "powershell-encoded-command",
        "description": "Execute Base64-encoded PowerShell payload",
        "destructive": false,
        "rollback": null
      }
    ],
    "expected_detections": [
      {
        "source": "openscrub",
        "rule_ref": "DETECT-PS-ENCODED-001",
        "detection_window_s": 30
      }
    ]
  }
}
```

### `POST /api/v1/scenarios`

Create a new scenario. Scenario YAML is validated against the schema
on write; the content hash is computed and stored.

**Request body:**
```json
{
  "yaml_content": "<scenario YAML as string>"
}
```

See [docs/scenario-authoring.md](scenario-authoring.md) for the
YAML format.

**Response 201:** Full scenario object (same as GET detail).

**Response 422:** Schema validation failed.

### `PUT /api/v1/scenarios/{id}`

Update a scenario. Creates a new `scenario_version` record; the
previous version is preserved for existing execution references.

**Request body:** Same as POST.

**Response 200:** Updated scenario object with new version.

### `DELETE /api/v1/scenarios/{id}`

Soft-delete a scenario. Existing execution records that reference
this scenario's versions are preserved. Deleted scenarios do not
appear in list responses but are retrievable via their execution
records.

**Response 204:** No content.

---

## Scenario Execution

### `POST /api/v1/scenarios/{id}/execute`

Queue a scenario for execution. Returns immediately with an
`execution_id`; poll for status via `GET /api/v1/executions/{exec_id}`.

**Request body:**
```json
{
  "dry_run": true,
  "target_scope": ["192.168.100.0/24"],
  "notes": "Weekly validation run — operator: alice",
  "detection_timeout_s": 60
}
```

| Field | Required | Default | Description |
|---|:-:|---|---|
| `dry_run` | No | `false` | If `true`, generates the execution plan without dispatching payloads. Always use dry-run first. |
| `target_scope` | Yes | — | List of CIDRs that steps may target. Must be a subset of `SECURELAB_TARGET_CIDR_ALLOWLIST`. |
| `notes` | No | — | Free-text operator notes recorded in the audit log. |
| `detection_timeout_s` | No | From config | Override the default detection window for this execution. |

**Response 202:**
```json
{
  "data": {
    "execution_id": "01HY...",
    "scenario_id": "01HX...",
    "scenario_version": "1.0.0",
    "scenario_version_hash": "sha256:abc123...",
    "mode": "dry_run",
    "status": "queued",
    "queued_at": "2027-11-01T14:00:00Z"
  }
}
```

### `GET /api/v1/executions/{exec_id}`

Get execution status and result.

**Response 200 (completed):**
```json
{
  "data": {
    "execution_id": "01HY...",
    "scenario_id": "01HX...",
    "scenario_version": "1.0.0",
    "mode": "live",
    "status": "completed",
    "operator_id": "01HZ...",
    "target_scope": ["192.168.100.0/24"],
    "notes": "Weekly validation run",
    "steps": [
      {
        "index": 1,
        "status": "completed",
        "dispatched_at": "2027-11-01T14:00:05Z",
        "completed_at": "2027-11-01T14:00:06Z"
      }
    ],
    "detection_summary": {
      "total_steps": 2,
      "steps_with_detections": 2,
      "overall_verdict": "detected"
    },
    "evidence_hash": "blake3:def456...",
    "citadel_emitted": true,
    "started_at": "2027-11-01T14:00:05Z",
    "completed_at": "2027-11-01T14:01:00Z"
  }
}
```

**Status values:** `queued` → `running` → `completed` | `failed` | `cancelled`

### `GET /api/v1/executions/{exec_id}/detections`

Get detection events captured during an execution. Requires v1.0.0.

**Response 200:**
```json
{
  "data": {
    "execution_id": "01HY...",
    "detections": [
      {
        "step_index": 2,
        "source": "openscrub",
        "verdict": "detected",
        "rule_ref": "DETECT-PS-ENCODED-001",
        "event_id": "openscrub-evt-999",
        "captured_at": "2027-11-01T14:00:35Z",
        "latency_ms": 29500
      },
      {
        "step_index": 2,
        "source": "apiguard",
        "verdict": "not_detected",
        "rule_ref": null,
        "event_id": null,
        "captured_at": null,
        "latency_ms": null
      }
    ],
    "overall_verdict": "partial"
  }
}
```

**Verdict values:** `detected` | `not_detected` | `inconclusive` | `timeout`

---

## Attack Library

### `GET /api/v1/attack-library`

List all attack primitives.

**Query parameters:** `tactic`, `technique`, `platform`, `page`, `per_page`
(same as scenarios).

**Response 200:**
```json
{
  "data": {
    "primitives": [
      {
        "id": "01HA...",
        "slug": "powershell-encoded-command",
        "title": "PowerShell Encoded Command",
        "mitre_technique": "T1059.001",
        "tactic": "execution",
        "platform": ["windows"],
        "destructive": false
      }
    ],
    "total": 1
  }
}
```

> **Note:** Payload content is not returned in list or detail
> responses. Operators with `operator` role may retrieve payload
> metadata; payload bytes are available only via the execution
> engine, not as a standalone export endpoint.

---

## ATT&CK Coverage

### `GET /api/v1/coverage`

Get the ATT&CK coverage matrix computed from execution results.

**Response 200:**
```json
{
  "data": {
    "computed_at": "2027-11-01T14:05:00Z",
    "total_techniques": 8,
    "techniques_with_scenarios": 8,
    "techniques_with_passing_executions": 5,
    "coverage_pct": 62.5,
    "tactics": {
      "execution": {
        "total": 3,
        "scenarios_exist": 3,
        "validated": 2
      },
      "persistence": {
        "total": 2,
        "scenarios_exist": 2,
        "validated": 1
      }
    },
    "navigator_layer_url": "/api/v1/coverage/navigator-layer"
  }
}
```

### `GET /api/v1/coverage/{technique_id}`

Get coverage detail for a single ATT&CK technique.

**Response 200:**
```json
{
  "data": {
    "technique_id": "T1059.001",
    "technique_name": "Command and Scripting Interpreter: PowerShell",
    "tactic": "execution",
    "scenarios": ["T1059.001-powershell-exec"],
    "last_execution": {
      "execution_id": "01HY...",
      "verdict": "detected",
      "executed_at": "2027-11-01T14:01:00Z"
    },
    "coverage_status": "validated"
  }
}
```

**Coverage status values:** `no_scenario` | `scenario_exists` | `executed` | `validated`

### `GET /api/v1/coverage/navigator-layer`

Download an ATT&CK Navigator layer JSON file representing the current
coverage state. Techniques with `validated` status are coloured; gaps
are unmarked.

**Response 200:** ATT&CK Navigator layer JSON (application/json).

---

## Related

- [docs/scenario-authoring.md](scenario-authoring.md) — YAML format
- [docs/configuration.md](configuration.md) — env vars
- [docs/architecture.md](architecture.md) — component overview
