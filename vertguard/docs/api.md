# VertGuard API Reference

HTTP API for VertGuard v0.1.x (Phase 4.1 scope). Additional endpoints
land in Phase 4.2 (ML layer) and Phase 4.3 (real-time video).

Base URL: `http://<host>:8091/api/v1/`

For the big-picture architecture, see [architecture.md](architecture.md).
For the request/response signing contract, see [citadel-integration.md](citadel-integration.md).

## Authentication

| Endpoint type | Authentication |
|---|---|
| Health, metrics | None (public) |
| Scan endpoints (Module 3, 4, 1) | JWT HS256 Bearer token |
| Admin endpoints | JWT with `admin` role |
| Webhook receivers | HMAC-SHA256 (per-source secret) |

JWT claims required:
- `sub` — caller identity
- `role` — one of `admin`, `operator`, `verifier`, `viewer`, `service`
- `exp` — expiry
- `iss` — must match `VERTGUARD_AUTH_ISSUER`

## Health

### `GET /api/v1/health`

Liveness + DB ping + module status.

**Response:**

```json
{
  "status":  "ok",
  "db":      "ok",
  "version": "0.1.0",
  "commit":  "abc1234",
  "built":   "2026-04-25T10:12:03Z",
  "modules": {
    "prompt":     "active",
    "threatfeed": "active",
    "media":      "active (C2PA only)",
    "phishing":   "inactive (Phase 4.2)",
    "identity":   "inactive (Phase 4.3)"
  },
  "integrations": {
    "citadel":    "connected",
    "threatflow": "connected"
  }
}
```

Status codes: `200 ok` | `503 db error or module failure`.

### `GET /metrics`

Prometheus scrape endpoint, unauthenticated.

## Module 3 — Prompt Injection

### `POST /api/v1/prompt/scan`

Scan a prompt for injection attacks.

**Auth:** JWT with `operator` or `service` role.

**Request:**

```json
{
  "input":   "Ignore previous instructions and...",
  "context": "user_chat_input"
}
```

| Field | Required | Notes |
|---|:-:|---|
| `input` | ✓ | Max 1 MiB |
| `context` | | One of `user_chat_input`, `authenticated_operator`, `internal_dev_tool`, `untrusted_third_party`, `untrusted_document_content` |

**Response (200):**

```json
{
  "classification": "BLOCKED",
  "confidence":     0.98,
  "matches": [
    {
      "pattern_id":   "LLM01.instruction_override.v1",
      "category":     "OWASP-LLM01",
      "atlas_technique": "AML.T0051.000",
      "description":  "Attempts to override prior instructions",
      "byte_range":   [0, 38],
      "confidence":   0.98
    }
  ],
  "worm_entry_id": "wo_0000000042",
  "scan_id":       "scan_abc123",
  "duration_ms":   3.2
}
```

**Status codes:**

- `200` — scan complete (any classification)
- `400` — input malformed or empty
- `401` — auth required or invalid
- `403` — role insufficient
- `413` — input exceeds max size
- `429` — rate limit exceeded
- `503` — pattern engine not loaded

### `GET /api/v1/prompt/scans/:scan_id`

Retrieve a past scan result.

**Auth:** JWT with `viewer+` role.

## Module 4 — AI Threat Intelligence Feed

### `GET /api/v1/threatfeed/iocs`

List AI-specific IOCs, paginated.

**Auth:** JWT with `viewer+` role.

**Query params:**

| Param | Notes |
|---|---|
| `since` | ISO 8601; return IOCs updated since |
| `technique` | Filter by MITRE ATLAS technique (e.g. `AML.T0051`) |
| `tactic` | Filter by ATLAS tactic |
| `confidence_gte` | Minimum confidence filter |
| `source` | Filter by source (`mitre-atlas`, `awesome-jailbreaks`, etc.) |
| `limit` | Page size (max 100, default 50) |
| `page` | Page number (default 1) |

**Response:**

```json
{
  "iocs": [
    {
      "type":         "ai_attack_pattern",
      "value":        "jailbreak.persona_takeover.v3",
      "source":       "awesome-jailbreaks",
      "technique":    "AML.T0051.000",
      "confidence":   0.91,
      "severity":     "high",
      "first_seen":   "2026-03-12T14:22:01Z",
      "last_seen":    "2026-04-19T10:15:00Z"
    }
  ],
  "total": 127,
  "page":  1,
  "has_next": true
}
```

### `POST /api/v1/threatfeed/atlas`

Map an observed behaviour to MITRE ATLAS techniques.

**Auth:** JWT with `viewer+` role.

**Request:**

```json
{ "observed_behaviour": "ML model exfiltration via inference API" }
```

**Response:**

```json
{
  "matches": [
    {
      "technique_id":     "AML.T0024",
      "name":             "Exfiltration via ML Inference API",
      "tactic":           "AML.TA0010",
      "confidence":       0.87,
      "atlas_url":        "https://atlas.mitre.org/techniques/AML.T0024"
    }
  ]
}
```

### `GET /api/v1/threatfeed/atlas/coverage`

Return VertGuard's coverage gaps against the ATLAS framework.

**Auth:** JWT with `viewer+` role.

## Module 1 — Media Authenticity

### `POST /api/v1/media/verify`

Verify a media file's authenticity (C2PA in Phase 4.1; ML deepfake
detection adds in Phase 4.2).

**Auth:** JWT with `operator+` role.

**Request:** `multipart/form-data` with `file` field, or JSON with
`url` field pointing at accessible media.

**Response (200) — authentic content:**

```json
{
  "authentic":    true,
  "provenance_chain": [
    { "actor": "Adobe Photoshop", "action": "c2pa.created", "ts": "..." }
  ],
  "signer":       "BBC Editorial",
  "certificate": {
    "issuer":     "BBC CA",
    "valid_to":   "2027-06-30"
  },
  "triple_hash":   "abc123...",
  "worm_entry_id": "wo_0000000043",
  "scan_id":       "scan_def456",
  "duration_ms":   42.8
}
```

**Response (200) — unknown (no manifest, Phase 4.1):**

```json
{
  "authentic":    "unknown",
  "reason":       "no C2PA manifest present",
  "note":         "Deepfake ML detection ships in Phase 4.2 (2027 Q3).",
  "triple_hash":  "abc123...",
  "scan_id":      "scan_...",
  "duration_ms":  15.3
}
```

**Response (200) — invalid:**

```json
{
  "authentic":    false,
  "reason":       "signature_invalid",
  "details":      "Signature chain verification failed: untrusted root",
  "scan_id":      "...",
  "duration_ms":  28.4
}
```

**Status codes:**

- `200` — scan complete (any classification)
- `400` — malformed input
- `401` — auth required
- `403` — role insufficient
- `413` — file exceeds max size (default 100 MiB)
- `415` — unsupported media type

### `GET /api/v1/media/scans/:scan_id`

Retrieve a past media verification result.

## Webhooks (inbound)

### `POST /api/v1/webhooks/threatflow`

Receive IOC updates from ThreatFlow.

**Auth:** HMAC-SHA256 via `X-Vertguard-Signature` + `X-Vertguard-Timestamp`.

Full wire format: [../../threatflow/docs/webhook-spec.md](../../threatflow/docs/webhook-spec.md).

### `POST /api/v1/webhooks/citadel`

(Future — Phase 4.2+) Receive MARSHAL decision notifications.

## Admin

### `POST /api/v1/admin/patterns/reload`

Hot-reload pattern registry without restart.

**Auth:** JWT with `admin` role.

**Response:**

```json
{
  "loaded_patterns": 127,
  "removed":         3,
  "added":           5,
  "version":         "2026-04-25-03"
}
```

### `POST /api/v1/admin/atlas/sync`

Trigger MITRE ATLAS sync.

**Auth:** JWT with `admin` role.

## Error response shape

Consistent across all endpoints:

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
  "error": "input exceeds maximum size of 1048576 bytes",
  "code":  "input_too_large",
  "details": { "max_bytes": 1048576, "received_bytes": 1572864 }
}
```

## Rate limits

Defaults per deployment (configurable):

| Endpoint | Limit |
|---|---|
| `POST /api/v1/prompt/scan` | 100 req/min per API key |
| `POST /api/v1/media/verify` | 30 req/min per API key |
| `GET /api/v1/threatfeed/iocs` | 100 req/min per API key |
| `POST /api/v1/threatfeed/atlas` | 60 req/min per API key |

Exceeding returns `429` with `Retry-After` header.

## Versioning

All endpoints under `/api/v1/`. Breaking changes bump to `/api/v2/`;
`/api/v1/` remains available for ≥ 12 months after v2 lands per the
ecosystem deprecation policy (see
[../../docs/deprecation-policy.md](../../docs/deprecation-policy.md)).

## Related

- [quick-start.md](quick-start.md)
- [architecture.md](architecture.md)
- [configuration.md](configuration.md)
- [../../docs/compatibility-matrix.md](../../docs/compatibility-matrix.md)
