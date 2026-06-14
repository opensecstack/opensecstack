# OpenScrub API

> v1.0.0 · port 8087 · prefix `/api/v1`. Machine-readable contract:
> [`api/openapi.yaml`](../api/openapi.yaml) — that file is the
> source of truth; this page is the human-readable companion. If the
> two disagree, the OpenAPI wins.

All endpoints under `/api/v1/*` require a Bearer JWT in the
`Authorization` header. The two exceptions are `/api/v1/health` and
`/api/v1/auth/login`. `/api/v1/metrics` is JWT-gated — counters leak
operational state and are not safe to expose unauthenticated; see
[Metrics](#metrics) below.

## Auth

### `POST /api/v1/auth/login`

Request:
```json
{ "username": "operator", "password": "…" }
```

Response `200`:
```json
{
  "access_token": "eyJ…",
  "token_type": "Bearer",
  "expires_at": "2026-05-10T11:23:00Z",
  "role": "operator",
  "sub": "operator-iuni"
}
```

`expires_at` is RFC-3339; the JWT itself also carries `exp`, `sub`,
and `role` claims. The dashboard parses `exp` from the token (not
the response field) to drop expired tokens client-side.

Errors:
- `400 bad_json` / `400 missing_field` — malformed body.
- `401 invalid_creds` — username or password wrong (timing-safe).
- `503 issuer_disabled` — operator did not seed `OPENSCRUB_USERS`;
  JWTs must be minted out-of-band against `OPENSCRUB_JWT_SECRET`.

## Health

### `GET /api/v1/health`

No auth. Returns `200`:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "db_ping": true,
  "dataplane_attached": true
}
```

`status` is `"ok"` or `"degraded"`. The dashboard derives a third
`down` level from request failure. `db_ping` and `dataplane_attached`
are booleans (not enums).

## Rules

### `GET /api/v1/rules?limit=&offset=&type=`

Response `200`:
```json
{
  "rules": [
    {
      "id": "01J…",
      "type": "blocklist",
      "cidr": "192.0.2.0/24",
      "ttl_seconds": 3600,
      "source": "operator",
      "created_at": "2026-05-09T10:23:00Z",
      "expires_at": "2026-05-09T11:23:00Z",
      "created_by": "operator-iuni"
    }
  ],
  "count": 1
}
```

- `type` ∈ `blocklist` | `ratelimit` | `syncookie`.
- `pps` present only on `ratelimit` rules; `port` present only on
  `syncookie` rules; `cidr` present on `blocklist` and `ratelimit`.

### `POST /api/v1/rules`

Request (one of):
```json
{ "type": "blocklist",  "cidr": "203.0.113.0/24", "ttl_seconds": 3600 }
{ "type": "ratelimit",  "cidr": "203.0.113.0/24", "pps": 1000, "ttl_seconds": 3600 }
{ "type": "syncookie",  "port": 443, "ttl_seconds": 86400 }
```

Response `201`: the created rule.

Errors:
- `400 invalid_cidr` — malformed CIDR.
- `400 dangerous_cidr` — `0.0.0.0/0`, `::/0`, or any prefix shorter
  than 8 bits is rejected by default.
- `409 conflict` — exact rule already exists.

### `GET /api/v1/rules/{id}`

Response `200`: bare rule object (same shape as a list element).
`404` if not found.

### `DELETE /api/v1/rules/{id}`

Response `204`. Side effects: clears the BPF map entry, writes an
audit row, emits a `rule_change` CITADEL event.

## Mitigations

### `GET /api/v1/mitigations?since=&rule_id=&limit=`

Query params (all optional):
- `since`: RFC-3339 timestamp; only rows with `started_at >= since`.
- `rule_id`: UUID; only rows for that rule.
- `limit`: 1..1000, default 200.

Response `200`:
```json
{
  "mitigations": [
    {
      "id": "01J…",
      "rule_id": "01J…",
      "started_at": "2026-05-09T10:24:01Z",
      "ended_at": null,
      "packets_dropped": 4823,
      "bytes_dropped": 2891204,
      "src_ip": "198.51.100.7",
      "emitted": true,
      "state": "sent",
      "attempts": 1
    }
  ],
  "count": 1
}
```

`emitted` (legacy boolean, kept for back-compat readers) indicates
whether the row was successfully posted to CITADEL. The richer
`state` column (`pending` / `sent` / `failed`) and `attempts`
counter are populated by migration 0002 — see
[data-model.md](data-model.md#mitigations) for the lifecycle.
`rule_id` may be `null` after the parent rule is deleted; the
event payload is reconstructed from the snapshot columns
(`rule_cidr`, `rule_type`, `rule_source`). The mitigation event itself uses CITADEL's `openscrub.mitigation`
schema — see [citadel-integration.md](citadel-integration.md).

## Metrics

### `GET /api/v1/metrics`

Prometheus exposition (text/plain). **JWT-gated** — counters reveal
operational state (rule counts, IOC pull cadence, CITADEL queue
depth) so the endpoint requires a Bearer token. Provision a
long-lived "readonly" JWT for Prometheus and pass it via
`authorization.credentials_file` in the scrape config (see
[deploy/prometheus.yml](../deploy/prometheus.yml)).

### `GET /api/v1/metrics/snapshot`

JSON snapshot for the dashboard:
```json
{
  "pps_passed": 1043221,
  "pps_dropped": 12482,
  "pps_ratelimited": 314,
  "syn_cookies_sent": 0,
  "rules_active": 1842,
  "rules_v4": 1820,
  "rules_v6": 22,
  "rules_ratelimit": 4,
  "rules_syncookie": 0,
  "ioc_pull_last_at": "2026-05-09T10:00:00Z",
  "ioc_pull_count": 12,
  "citadel_queue_depth": 0,
  "dataplane_attached": true,
  "snapshot_at": "2026-05-09T10:25:00Z"
}
```

For ad-hoc PromQL, query the Prometheus instance directly — OpenScrub
does not proxy PromQL through its own API surface.

## Errors

All errors share the shape `{"error": {"code": "<code>", "message": "<human>"}}`.
HTTP status follows the standard mapping (400 / 401 / 403 / 404 /
409 / 500 / 503).

## Versioning

The `/api/v1` prefix is part of the contract. Breaking changes ship
under `/api/v2` alongside `v1` for at least one minor release. See
the ecosystem [deprecation policy](../../docs/deprecation-policy.md).
