# ThreatFlow API Reference

Base URL: `http://localhost:8091/api/v1`

All endpoints return `application/json` unless otherwise noted. Mutation endpoints will require JWT authentication once the auth layer is implemented.

---

## Health

### GET /health

Returns the service health status.

**Response 200:**
```json
{
  "status": "ok",
  "service": "threatflow"
}
```

### GET /version

Returns the build version.

**Response 200:**
```json
{
  "version": "0.1.0",
  "git_commit": "abc1234",
  "build_date": "2026-03-31T10:00:00Z"
}
```

---

## IOCs (Indicators of Compromise)

### GET /iocs

List all IOCs with optional filters.

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `type` | string | Filter by IOC type (e.g. `ipv4-addr`, `domain-name`, `url`, `file:hashes.SHA-256`) |
| `source` | string | Filter by feed source name |
| `confidence_min` | number | Minimum confidence score (0–100) |
| `since` | ISO 8601 | Only IOCs ingested after this timestamp |
| `limit` | int | Page size (default: 50, max: 100) |
| `offset` | int | Pagination offset |

**Response 200:**
```json
{
  "items": [
    {
      "id": "ioc-550e8400-e29b-41d4-a716-446655440000",
      "type": "ipv4-addr",
      "value": "198.51.100.42",
      "source": "alienvault-otx",
      "confidence": 85,
      "ttp": ["T1071.001"],
      "first_seen": "2026-03-15T10:00:00Z",
      "last_seen": "2026-03-30T14:22:00Z",
      "stix_id": "indicator--abc123"
    }
  ],
  "total": 1
}
```

### POST /iocs

Ingest a new IOC. The IOC is normalised to STIX 2.1 internally.

**Request Body:**
```json
{
  "type": "ipv4-addr",
  "value": "198.51.100.42",
  "source": "manual",
  "confidence": 90,
  "description": "C2 callback IP observed in phishing campaign",
  "ttp": ["T1071.001", "T1566.001"],
  "tags": ["phishing", "c2"],
  "expiry": "2026-06-30T00:00:00Z"
}
```

**Response 202:**
```json
{
  "status": "accepted"
}
```

When CITADEL integration is enabled, the response will include:
```json
{
  "status": "accepted",
  "ioc_id": "ioc-...",
  "stix_id": "indicator--...",
  "worm_entry_id": "entry-...",
  "chain_hash": "a1b2c3..."
}
```

### GET /iocs/{id}

Retrieve a single IOC by its internal ID.

**Response 200:** Single IOC object (same shape as list items).

**Response 404:**
```json
{
  "error": "ioc not found",
  "id": "ioc-..."
}
```

---

## STIX 2.1 Bundles

### GET /stix/bundles

List available STIX 2.1 bundles.

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `since` | ISO 8601 | Bundles created after this timestamp |
| `limit` | int | Page size (default: 50) |

**Response 200:**
```json
{
  "bundles": [
    {
      "id": "bundle--abc123",
      "created": "2026-03-30T14:00:00Z",
      "object_count": 42,
      "source": "threatflow-export"
    }
  ],
  "total": 1
}
```

### POST /stix/bundles

Ingest a STIX 2.1 bundle. All objects in the bundle are parsed, validated, and stored.

**Request Body:** A valid STIX 2.1 bundle:
```json
{
  "type": "bundle",
  "id": "bundle--550e8400-e29b-41d4-a716-446655440000",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--abc123",
      "created": "2026-03-30T10:00:00Z",
      "modified": "2026-03-30T10:00:00Z",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "pattern_type": "stix",
      "valid_from": "2026-03-30T10:00:00Z"
    }
  ]
}
```

**Response 202:**
```json
{
  "status": "accepted"
}
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "human-readable error message",
  "code": "MACHINE_READABLE_CODE"
}
```

| Status | When |
|--------|------|
| 400 | Invalid JSON body or malformed parameters |
| 401 | Missing or invalid authentication (when auth is enabled) |
| 403 | CITADEL MARSHAL returned REFUSE or HARD_STOP |
| 404 | Resource not found |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
