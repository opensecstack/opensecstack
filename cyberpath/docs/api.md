# CyberPath API Reference

HTTP API for CyberPath v1.0.0 — the first stable release (shipped
2026-05-09, Modules 1–8 feature-complete): learning path engine, quiz
engine, Docker-based labs, Wasm sandbox labs, certification issuance
and governed revocation, NIS2 Compass coverage and gap-driven
recommendations, and content versioning. All endpoints below are live.

Base URL: `http://<host>:8086/api/v1/`

For the big-picture architecture, see [architecture.md](architecture.md).
For the CITADEL evidence wire format, see
[citadel-integration.md](citadel-integration.md).

## Authentication

| Endpoint type | Authentication |
|---|---|
| Health, readiness, metrics | None (public) |
| `auth/*` | None (login / signup) |
| Learner endpoints | JWT HS256 Bearer (issued via `/auth/login`) |
| NIS2 Compass coverage / recommend | JWT Bearer, any authenticated user — **known gap:** not yet restricted to the `service` role; see [ADR-014](../../adrs/ADR-014-cyberpath-nis2compass-integration-direction.md) implementation note |
| Admin endpoints | JWT with `admin` role |

JWT shape inherited from `opensecstack/sdk`:

- `sub` — caller user id
- `role` — one of `learner`, `instructor`, `admin`, `service`
- `tenant` — optional tenant identifier
- `iss` — must match `CYBERPATH_AUTH_ISSUER`
- `exp` — expiry, capped by `CYBERPATH_AUTH_TOKEN_TTL`

Pass as `Authorization: Bearer <jwt>`.

## Health & metrics

### `GET /healthz`

Liveness only. Returns `200` whenever the process is up.

### `GET /readyz`

Readiness — DB ping plus integration health.

```json
{
  "status":  "ok",
  "db":      "ok",
  "modules": {
    "path":   "active",
    "quiz":   "active",
    "lab":    "active (docker)",
    "cert":   "active"
  },
  "integrations": {
    "citadel":     "connected",
    "nis2compass": "connected",
    "irflow":      "standalone"
  }
}
```

`200` ok | `503` dependency unhealthy.

### `GET /metrics`

Prometheus scrape, unauthenticated, on the API port.

## Auth

### `POST /api/v1/auth/login`

**Request:**

```json
{ "email": "alice@example.test", "password": "correct horse battery staple" }
```

**Response (200):**

```json
{
  "access_token":  "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "rt_01J0...",
  "token_type":    "Bearer",
  "expires_in":    28800,
  "user": {
    "id":           "01HX...",
    "email":        "alice@example.test",
    "display_name": "Alice",
    "locale":       "sq",
    "role":         "learner"
  }
}
```

`401` invalid credentials | `429` rate-limited | `403` account locked.

### `POST /api/v1/auth/refresh`

**Request:**

```json
{ "refresh_token": "rt_01J0..." }
```

**Response (200):**

```json
{
  "access_token":  "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "rt_01J0...",
  "expires_in":    28800
}
```

Refresh tokens rotate on every call; the old token is denylisted.

## Tracks

### `GET /api/v1/tracks`

List visible tracks. Honours `Accept-Language: sq|en`.

**Query params:** `audience`, `nis2_measure`, `cert_offered` (bool),
`limit`, `page`.

**Response (200):**

```json
{
  "tracks": [
    {
      "id":               "01HX...",
      "slug":             "nis2-art21-awareness",
      "title":            "NIS2 Article 21 awareness",
      "audience":         "all-staff",
      "nis2_measures":    ["art21.g","art21.a","art21.b","art21.i"],
      "estimated_minutes": 90,
      "lab_required":     false,
      "cert_offered":     true,
      "track_version":    "1.0.0"
    }
  ],
  "total": 3,
  "page":  1
}
```

### `GET /api/v1/tracks/{id}`

Track detail. `id` accepts either ULID or slug.

```json
{
  "id":              "01HX...",
  "slug":            "nis2-art21-awareness",
  "title_sq":        "Vetëdija për Nenin 21 të NIS2",
  "title_en":        "NIS2 Article 21 awareness",
  "description_sq":  "...",
  "description_en":  "...",
  "track_version":   "1.0.0",
  "modules": [
    { "id": "01HM...", "order": 1, "title_en": "Scope and obligations", "lesson_count": 4 }
  ],
  "labs":            [],
  "cert_offered":    true,
  "cert_expires_after_days": 1095
}
```

### `GET /api/v1/tracks/{id}/modules`

Returns modules with their lessons.

```json
{
  "modules": [
    {
      "id":    "01HM...",
      "order": 1,
      "title_en": "Scope and obligations",
      "lessons": [
        { "id": "01HL...", "order": 1, "title_en": "Who NIS2 applies to", "has_quiz": true, "has_lab": false }
      ]
    }
  ]
}
```

## Lessons

### `GET /api/v1/lessons/{id}`

```json
{
  "id":                 "01HL...",
  "module_id":          "01HM...",
  "title_sq":           "...",
  "title_en":           "Who NIS2 applies to",
  "body_sq":            "# ...",
  "body_en":            "# ...",
  "content_version_id": "01HC...",
  "content_hash":       "blake3:...",
  "quiz_id":            "01HQ...",
  "lab_id":             null
}
```

### `POST /api/v1/lessons/{id}/complete`

**Request:**

```json
{ "time_spent_seconds": 412 }
```

**Response (200):**

```json
{
  "completion_id":      "01J0...",
  "lesson_id":          "01HL...",
  "content_version_id": "01HC...",
  "score":              1.0,
  "completed_at":       "2026-04-26T11:02:14Z",
  "evidence_hash":      "blake3:8a72...",
  "citadel_emitted":    "queued"
}
```

`409` if already completed for this `content_version_id` (idempotent;
returns the existing completion).

## Quizzes

### `POST /api/v1/quizzes/{id}/submit`

**Request:**

```json
{
  "answers": [
    { "question_id": "q1", "choice_ids": ["c2"] },
    { "question_id": "q2", "choice_ids": ["c1","c4"] }
  ]
}
```

**Response (200):**

```json
{
  "submission_id":  "01J0...",
  "score":          0.87,
  "passed":         true,
  "pass_threshold": 0.7,
  "per_question": [
    { "question_id": "q1", "correct": true,  "earned": 1.0 },
    { "question_id": "q2", "correct": false, "earned": 0.5 }
  ],
  "completion_id":  "01J0...",
  "citadel_emitted":"queued"
}
```

`422` malformed answer set | `409` past quiz cooldown still active.

## Labs

### `POST /api/v1/labs/{id}/start`

Provisions a per-session lab environment — Docker or wasmtime
(Module 4, Wasm Sandbox Labs), depending on the lab image — both
runtimes shipped in v1.0.0. Returns a WebSocket URL for the browser
terminal.

**Response (200):**

```json
{
  "session_id":  "01J0...",
  "runtime":     "docker",
  "ws_url":      "ws://localhost:8086/api/v1/ws/labs/01J0.../term",
  "image":       "opensecstack/cyberpath-lab-phish:1.0.0@sha256:...",
  "started_at":  "2026-04-26T11:05:00Z",
  "expires_at":  "2026-04-26T13:05:00Z"
}
```

`409` learner already has an active session for this lab | `429` per-
tenant lab quota exceeded | `503` runtime unavailable.

### `POST /api/v1/labs/{id}/stop`

Tears the session down and finalises `lab_sessions.ended_at`.

```json
{ "session_id": "01J0...", "ended_at": "2026-04-26T11:42:00Z", "exit_status": "stopped_by_user" }
```

### `GET /api/v1/labs/{id}/status`

```json
{
  "session_id":      "01J0...",
  "state":           "running",
  "runtime":         "docker",
  "started_at":      "2026-04-26T11:05:00Z",
  "expires_at":      "2026-04-26T13:05:00Z",
  "resource_metrics": {
    "cpu_seconds":  42.1,
    "memory_bytes": 178257920
  }
}
```

## User progress & certifications

### `GET /api/v1/users/{id}/progress`

```json
{
  "user_id": "01HX...",
  "tracks": [
    {
      "track_id":      "01HX...",
      "track_slug":    "nis2-art21-awareness",
      "track_version": "1.0.0",
      "started_at":    "2026-04-26T10:00:00Z",
      "completed_at":  null,
      "lessons_total": 12,
      "lessons_done":  4,
      "quiz_avg":      0.81
    }
  ]
}
```

### `GET /api/v1/users/{id}/certifications`

```json
{
  "user_id": "01HX...",
  "certifications": [
    {
      "id":                "01CE...",
      "track_id":          "01HX...",
      "track_slug":        "phishing-recognition",
      "track_version":     "1.4.0",
      "issued_at":         "2027-04-22T08:11:02Z",
      "expires_at":        "2028-04-22T08:11:02Z",
      "evidence_hash":     "blake3:...",
      "citadel_ledger_id": "wo_0000004212",
      "signature":         "ed25519:...",
      "download_url":      "/api/v1/certifications/01CE.../pdf"
    }
  ]
}
```

Certifications are issued by the Module 5 certification module
(Ed25519-signed, per-track). This endpoint returns the caller's
issued certifications; an empty list simply means the user has none
yet.

## Certifications

### `POST /api/v1/certifications/issue`

Issues a signed, hash-anchored certification for a completed track.
`admin` role or the auto-issue path triggered by track completion.
Emits a `cyberpath.certification.issued` WORM audit event to CITADEL.

### `GET /api/v1/me/certifications`

Lists the authenticated caller's own certifications. Same response
shape as `GET /api/v1/users/{id}/certifications` above.

### `DELETE /api/v1/admin/certifications/{id}/revoke`

Revokes a certification. `admin` role. Runs a CITADEL MARSHAL
governance evaluation before proceeding — a `REFUSE`/`HARD_STOP`
verdict blocks the request with `403`. Emits a
`cyberpath.certification.revoked` WORM audit event unconditionally.
See [../README.md § Certification governance](../README.md) and
[citadel-integration.md](citadel-integration.md) for the full detail,
including the documented fail-open and placeholder-verifier
trade-offs.

## NIS2 Compass integration (v1.0.0)

Per [ADR-014](../../adrs/ADR-014-cyberpath-nis2compass-integration-direction.md),
this is a **pull** integration: NIS2 Compass calls these two `GET`
endpoints; CyberPath never calls out to NIS2 Compass except for the
`/healthz` connectivity probe backing `/readyz`'s
`integrations.nis2compass` field (see [configuration.md](configuration.md)).
Full narrative spec (partially aspirational — verify against the
implementation below before integrating) in
[nis2-integration.md](nis2-integration.md).

### `GET /api/v1/coverage/{user_id}`

NIS2 Article 21 measure coverage for a user, computed live from the
user's completed lessons against every published track's NIS2
measure mappings.

```json
{
  "user_id":   "01HX...",
  "coverage":  [
    { "track_id": "01HX...", "track_slug": "nis2-art21-awareness", "nis2_refs": ["art21.g","art21.a"], "pct_complete": 100 }
  ],
  "gaps": [
    { "track_id": "01HY...", "track_slug": "phishing-recognition", "nis2_refs": ["art21.g"], "pct_complete": 50 }
  ],
  "generated": "live"
}
```

A track appears in `coverage` at 100% completion, otherwise in `gaps`.
Tracks with no NIS2 measure mappings are omitted entirely. Falls back
to `"generated": "stub"` with both lists empty when the DB-backed
stores are not wired (dev only).

### `GET /api/v1/cyberpath/recommend?gap=art21_g`

Tracks that address a documented gap, drawn from CyberPath's own
published track catalogue. `gap` accepts either the dotted
(`art21.g`) or underscored (`art21_g`) form; the response echoes the
gap as received and adds the normalised dotted `measure`.

```json
{
  "gap":     "art21_g",
  "measure": "art21.g",
  "recommendations": [
    {
      "track_id":            "01HX...",
      "track_slug":          "nis2-art21-awareness",
      "title_en":            "NIS2 Article 21 awareness",
      "addresses_measures":  ["art21.g","art21.a","art21.b","art21.i"],
      "priority":            "primary"
    }
  ]
}
```

A track's priority is `"primary"` when the requested measure is its
first (content-authored primary) NIS2 mapping, `"secondary"` for any
other match. `audience`, `estimated_minutes`, `lab_required` and
`certification` — present in earlier drafts of this doc — are **not**
returned: `db.Track` carries no such fields, and CyberPath does not
fabricate values it doesn't actually have.

`400 unknown_gap` when `gap` does not normalise to one of the
Article 21(2)(a–j) measures.

## Webhooks (inbound)

### `POST /api/v1/webhooks/irflow/incident_trigger`

IRFlow delivers an incident summary; CyberPath maps it to a
recommended track and surfaces the recommendation in the learner's
dashboard. HMAC-SHA256 via `X-IRFlow-Signature` +
`X-IRFlow-Timestamp`. Wire format: shared with the rest of the
ecosystem (see `opensecstack/sdk`).

## Admin

> There is no HTTP endpoint for importing tracks. Track import is a
> CLI-only operation — run `cyberpath-cli track import <track.yaml>`
> against the content directory (see [quick-start.md](quick-start.md)
> and [troubleshooting.md](troubleshooting.md)). `internal/api/server.go`
> registers no `/admin/tracks/import` route and no handler for it
> exists in `internal/api/handlers`.

### `POST /api/v1/admin/content/reload`

Re-reads the content directory (`CYBERPATH_CONTENT_PATH`) and
inserts any new `content_versions` rows. Returns inserted count.

## Error response shape

```json
{
  "error":   "human-readable description",
  "code":    "machine_parseable_code",
  "details": { /* optional */ }
}
```

Example:

```json
{
  "error": "lesson already completed for this content_version_id",
  "code":  "completion_idempotent",
  "details": { "existing_completion_id": "01J0..." }
}
```

## Rate limits

| Endpoint | Limit |
|---|---|
| `POST /api/v1/auth/login` | 10 req/min per IP |
| `POST /api/v1/lessons/{id}/complete` | 60 req/min per learner |
| `POST /api/v1/labs/{id}/start` | 5 req/min per learner |
| `GET /api/v1/coverage/{id}` | 120 req/min per service token |

`429` with `Retry-After` header on exceed.

## Versioning

All endpoints under `/api/v1/`. Breaking changes bump to `/api/v2/`
with `/api/v1/` available for ≥ 12 months per the ecosystem
deprecation policy.

## See also

- [quick-start.md](quick-start.md)
- [configuration.md](configuration.md)
- [architecture.md](architecture.md)
- [citadel-integration.md](citadel-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [troubleshooting.md](troubleshooting.md)
