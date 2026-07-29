# ThreatFlow Webhook Specification

This document defines the webhook protocol used by ThreatFlow for real-time event exchange with other opensecstack platforms. It covers inbound and outbound webhooks, signature verification, retry policies, dead-letter handling, and payload schemas.

---

## Overview

ThreatFlow uses webhooks for two purposes:

1. **Inbound webhooks** -- receive events from APIGuard, CITADEL, and external sources
2. **Outbound webhooks** -- push events to IRFlow, NIS2Compass, and OpenCSIRT

All webhooks use JSON payloads over HTTPS (or HTTP in development) with HMAC-SHA256 signature verification.

---

## HMAC-SHA256 Signature Format

Every webhook request (inbound and outbound) carries a cryptographic signature to ensure authenticity and integrity.

### Signature Headers

| Header | Description |
|--------|-------------|
| `X-ThreatFlow-Signature` | `sha256=<hex-encoded HMAC-SHA256 digest>` |
| `X-ThreatFlow-Timestamp` | Unix timestamp (seconds) when the request was signed |
| `X-ThreatFlow-Event` | Event type string (e.g. `apiguard.scan.completed`) |
| `X-ThreatFlow-Delivery` | Unique delivery ID (UUID v4) for idempotency |

### Signature Computation

The HMAC is computed over a canonical string:

```
canonical = timestamp + "." + raw_request_body
signature = HMAC-SHA256(webhook_secret, canonical)
```

The `X-ThreatFlow-Signature` header value is `sha256=` followed by the lowercase hex encoding of the HMAC digest.

### Timestamp Validation

Receivers should reject requests where the timestamp differs from the current time by more than **300 seconds** (5 minutes) to prevent replay attacks.

---

## Verifying a Webhook Signature

### Go

```go
package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxTimestampSkew = 300 // seconds

// VerifyWebhook validates the HMAC-SHA256 signature on an inbound webhook.
// Returns nil if the signature is valid, an error otherwise.
func VerifyWebhook(secret string, r *http.Request, body []byte) error {
	sigHeader := r.Header.Get("X-ThreatFlow-Signature")
	tsHeader := r.Header.Get("X-ThreatFlow-Timestamp")

	if sigHeader == "" || tsHeader == "" {
		return fmt.Errorf("missing signature or timestamp header")
	}

	// Validate timestamp to prevent replay attacks
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	skew := math.Abs(float64(time.Now().Unix() - ts))
	if skew > maxTimestampSkew {
		return fmt.Errorf("timestamp skew %0.fs exceeds maximum %ds", skew, maxTimestampSkew)
	}

	// Compute expected signature
	canonical := tsHeader + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	if !hmac.Equal([]byte(expected), []byte(sigHeader)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}
```

### Python

```python
import hashlib
import hmac
import time


MAX_TIMESTAMP_SKEW = 300  # seconds


def verify_webhook(secret: str, timestamp: str, signature: str, body: bytes) -> bool:
    """Verify an inbound ThreatFlow webhook signature.

    Args:
        secret: The shared webhook secret.
        timestamp: Value of the X-ThreatFlow-Timestamp header.
        signature: Value of the X-ThreatFlow-Signature header.
        body: Raw request body bytes.

    Returns:
        True if the signature is valid.

    Raises:
        ValueError: If the timestamp is expired or the signature is invalid.
    """
    # Validate timestamp
    ts = int(timestamp)
    if abs(time.time() - ts) > MAX_TIMESTAMP_SKEW:
        raise ValueError(
            f"Timestamp skew exceeds {MAX_TIMESTAMP_SKEW}s — possible replay attack"
        )

    # Compute expected signature
    canonical = f"{timestamp}.".encode() + body
    expected = "sha256=" + hmac.new(
        secret.encode(), canonical, hashlib.sha256
    ).hexdigest()

    # Constant-time comparison
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Webhook signature mismatch")

    return True


# Flask example
from flask import Flask, request, abort

app = Flask(__name__)
WEBHOOK_SECRET = "your-shared-secret"


@app.route("/api/v1/webhooks/apiguard", methods=["POST"])
def apiguard_webhook():
    try:
        verify_webhook(
            secret=WEBHOOK_SECRET,
            timestamp=request.headers.get("X-ThreatFlow-Timestamp", ""),
            signature=request.headers.get("X-ThreatFlow-Signature", ""),
            body=request.get_data(),
        )
    except ValueError as e:
        abort(401, str(e))

    payload = request.get_json()
    # Process the webhook event...
    return {"received": True}, 200
```

### TypeScript

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";

const MAX_TIMESTAMP_SKEW = 300; // seconds

interface WebhookHeaders {
    "x-threatflow-signature": string;
    "x-threatflow-timestamp": string;
    "x-threatflow-event": string;
    "x-threatflow-delivery": string;
}

/**
 * Verify an inbound ThreatFlow webhook signature.
 *
 * @param secret - The shared webhook secret
 * @param timestamp - Value of X-ThreatFlow-Timestamp header
 * @param signature - Value of X-ThreatFlow-Signature header
 * @param body - Raw request body as a string or Buffer
 * @throws Error if the timestamp is expired or the signature is invalid
 */
export function verifyWebhook(
    secret: string,
    timestamp: string,
    signature: string,
    body: string | Buffer,
): void {
    // Validate timestamp
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts)) {
        throw new Error("Invalid timestamp header");
    }
    const skew = Math.abs(Math.floor(Date.now() / 1000) - ts);
    if (skew > MAX_TIMESTAMP_SKEW) {
        throw new Error(
            `Timestamp skew ${skew}s exceeds maximum ${MAX_TIMESTAMP_SKEW}s`,
        );
    }

    // Compute expected signature
    const canonical = `${timestamp}.${body}`;
    const expected =
        "sha256=" +
        createHmac("sha256", secret).update(canonical).digest("hex");

    // Constant-time comparison
    const expectedBuf = Buffer.from(expected);
    const signatureBuf = Buffer.from(signature);
    if (
        expectedBuf.length !== signatureBuf.length ||
        !timingSafeEqual(expectedBuf, signatureBuf)
    ) {
        throw new Error("Webhook signature mismatch");
    }
}

// Express.js example
import express from "express";

const app = express();
const WEBHOOK_SECRET = process.env.THREATFLOW_WEBHOOK_SECRET!;

app.post(
    "/api/v1/webhooks/apiguard",
    express.raw({ type: "application/json" }),
    (req, res) => {
        try {
            verifyWebhook(
                WEBHOOK_SECRET,
                req.headers["x-threatflow-timestamp"] as string,
                req.headers["x-threatflow-signature"] as string,
                req.body,
            );
        } catch (err) {
            return res.status(401).json({ error: (err as Error).message });
        }

        const payload = JSON.parse(req.body.toString());
        // Process the webhook event...
        res.json({ received: true });
    },
);
```

---

## Inbound Webhooks

ThreatFlow receives events from the following sources.

### POST /api/v1/webhooks/apiguard

Receives scan completion and critical finding events from APIGuard.

**Event types:** `apiguard.scan.completed`, `apiguard.finding.critical`

**Payload schema:**

```json
{
  "event_type": "apiguard.scan.completed",
  "scan_id": "scan-123",
  "target": "https://api.example.com",
  "findings": [
    {
      "id": "finding-456",
      "severity": "critical",
      "title": "SQL Injection in /api/v1/users",
      "endpoint_path": "/api/users",
      "owasp_id": "API1:2023",
      "target_ip": "203.0.113.10",
      "target_domain": "api.example.com"
    }
  ],
  "completed_at": "2026-03-31T10:00:00Z"
}
```

**Response (200 OK):**

```json
{
  "received": true,
  "iocs_extracted": 2,
  "iocs_new": 1,
  "iocs_existing": 1,
  "correlation_matches": 3
}
```

**Error responses:**

| Status | Meaning |
|--------|---------|
| `401` | Signature verification failed |
| `400` | Malformed payload or missing required fields |
| `429` | Rate limit exceeded (100 requests/minute) |
| `500` | Internal processing error (will be retried by sender) |

### POST /api/v1/webhooks/citadel

Receives governance events from CITADEL (MARSHAL decisions, AUGUR advisories; VIGIL alerts once VIGIL ships — CITADEL v2.0, design-stage as of v1.0.0).

**Event types:** `citadel.marshal.decision`, `citadel.augur.advisory`, `citadel.vigil.alert` (planned)

**Payload schema:**

```json
{
  "event_type": "citadel.marshal.decision",
  "decision_id": "dec-789",
  "action_type": "bulk_ioc_ingest",
  "result": "EXECUTE",
  "conditions": [],
  "evaluated_at": "2026-03-31T10:05:00Z"
}
```

### POST /api/v1/webhooks/generic

Receives events from custom or third-party sources. The payload must include `event_type` and `source` fields at minimum.

**Payload schema:**

```json
{
  "event_type": "custom.ioc.report",
  "source": "third-party-scanner",
  "data": {
    "iocs": [
      { "type": "ipv4-addr", "value": "198.51.100.42" }
    ]
  },
  "timestamp": "2026-03-31T10:00:00Z"
}
```

---

## Outbound Webhooks

ThreatFlow pushes events to the following consumers.

### IRFlow: Correlation Matches and IOC Updates

**Target:** `POST http://irflow:8083/api/v1/webhooks/threatflow`

**Event types:** `threatflow.correlation.match`, `threatflow.ioc.ingested`

**Payload schema (`threatflow.correlation.match`):**

```json
{
  "event_type": "threatflow.correlation.match",
  "incident_id": "inc-20260331-001",
  "bundle_id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "iocs": [
    {
      "stix_id": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
      "type": "ipv4-addr",
      "value": "198.51.100.42",
      "confidence": 85,
      "ttp": ["T1071.001"],
      "source": "alienvault-otx",
      "first_seen": "2026-03-15T10:00:00Z"
    }
  ],
  "stix_bundle_url": "http://threatflow:8091/api/v1/stix/bundles/bundle--a1b2c3d4",
  "matched_at": "2026-03-31T10:10:00Z"
}
```

**Payload schema (`threatflow.ioc.ingested`):**

```json
{
  "event_type": "threatflow.ioc.ingested",
  "ioc_id": "ioc-550e8400-e29b-41d4-a716-446655440000",
  "type": "ipv4-addr",
  "value": "198.51.100.42",
  "confidence": 85,
  "source": "alienvault-otx",
  "stix_id": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
  "ttp": ["T1071.001"],
  "ingested_at": "2026-03-31T10:00:00Z"
}
```

### NIS2Compass: Evidence Notifications

**Target:** `POST http://nis2compass:5000/api/v1/webhooks/threatflow`

**Event types:** `threatflow.bundle.exported`

**Payload schema:**

```json
{
  "event_type": "threatflow.bundle.exported",
  "bundle_id": "bundle--f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "ioc_count": 15,
  "tags": ["supply-chain"],
  "date_range": {
    "since": "2026-01-01T00:00:00Z",
    "until": "2026-03-31T23:59:59Z"
  },
  "download_url": "http://threatflow:8091/api/v1/stix/bundles/bundle--f47ac10b",
  "exported_at": "2026-03-31T10:00:00Z"
}
```

### OpenCSIRT: Advisory Import Bundles

**Target:** `POST http://opencsirt:8092/api/v1/advisories/import`

**Event types:** `threatflow.bundle.exported` (with `consumer: "opencsirt"`)

The payload is a full STIX 2.1 bundle with `Content-Type: application/stix+json;version=2.1`. See the [STIX integration docs](stix-integration.md) for the bundle format.

---

## Retry Policy

When an outbound webhook delivery fails (non-2xx response or network error), ThreatFlow retries using exponential backoff.

### Retry Schedule

| Attempt | Delay | Total Elapsed |
|---------|-------|---------------|
| 1 (initial) | 0s | 0s |
| 2 (first retry) | 30s | 30s |
| 3 (second retry) | 60s | 90s |
| 4 (third retry) | 120s | 210s |

After 4 attempts (1 initial + 3 retries), the delivery is marked as **failed** and moved to the dead-letter queue.

### Retryable vs Non-Retryable Errors

| Status Code | Retryable | Reason |
|-------------|-----------|--------|
| `2xx` | N/A | Success -- no retry needed |
| `401` | No | Authentication failure -- retrying will not help |
| `403` | No | Authorization failure -- retrying will not help |
| `404` | No | Endpoint not found -- configuration error |
| `408` | Yes | Request timeout |
| `429` | Yes | Rate limited -- retry after `Retry-After` header if present |
| `500` | Yes | Internal server error |
| `502` | Yes | Bad gateway |
| `503` | Yes | Service unavailable |
| `504` | Yes | Gateway timeout |
| Network error | Yes | Connection refused, DNS failure, timeout |

### Idempotency

Every webhook delivery includes a unique `X-ThreatFlow-Delivery` header (UUID v4). Receivers should use this ID to deduplicate deliveries in case a successful response is lost and the webhook is retried.

---

## Dead-Letter Queue

Failed webhook deliveries (after all retry attempts are exhausted) are stored in the dead-letter queue for manual inspection and replay.

### Viewing Dead-Letter Items

```http
GET /api/v1/webhooks/dead-letter?status=failed&since=2026-03-01
Authorization: Bearer ${ADMIN_API_KEY}
```

**Response:**

```json
{
  "data": [
    {
      "id": "dl-001",
      "delivery_id": "d4e5f6a7-b8c9-0123-4567-89abcdef0123",
      "target_url": "http://irflow:8083/api/v1/webhooks/threatflow",
      "event_type": "threatflow.correlation.match",
      "payload": { "..." : "..." },
      "attempts": 4,
      "last_attempt_at": "2026-03-31T10:03:30Z",
      "last_status_code": 503,
      "last_error": "Service Unavailable",
      "created_at": "2026-03-31T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1
  }
}
```

### Replaying a Dead-Letter Item

```http
POST /api/v1/webhooks/dead-letter/{id}/replay
Authorization: Bearer ${ADMIN_API_KEY}
```

**Response (202 Accepted):**

```json
{
  "id": "dl-001",
  "status": "retrying",
  "next_attempt_at": "2026-03-31T10:10:00Z"
}
```

### Purging Dead-Letter Items

```http
DELETE /api/v1/webhooks/dead-letter?before=2026-03-01
Authorization: Bearer ${ADMIN_API_KEY}
```

---

## Webhook Registration API (Planned)

A self-service webhook registration API is planned for v0.5+. This will allow external consumers to register their own endpoints for ThreatFlow events without manual configuration.

### Register a Webhook Endpoint

```http
POST /api/v1/webhooks/subscriptions
Content-Type: application/json
Authorization: Bearer ${API_KEY}

{
  "name": "My SIEM Integration",
  "url": "https://siem.example.com/webhooks/threatflow",
  "events": [
    "threatflow.ioc.ingested",
    "threatflow.correlation.match"
  ],
  "secret": "my-webhook-secret-min-32-chars-long",
  "active": true,
  "metadata": {
    "team": "security-operations",
    "environment": "production"
  }
}
```

**Response (201 Created):**

```json
{
  "id": "sub-001",
  "name": "My SIEM Integration",
  "url": "https://siem.example.com/webhooks/threatflow",
  "events": [
    "threatflow.ioc.ingested",
    "threatflow.correlation.match"
  ],
  "active": true,
  "created_at": "2026-03-31T10:00:00Z",
  "last_delivery_at": null,
  "delivery_stats": {
    "total": 0,
    "successful": 0,
    "failed": 0
  }
}
```

### List Webhook Subscriptions

```http
GET /api/v1/webhooks/subscriptions
Authorization: Bearer ${API_KEY}
```

### Update a Webhook Subscription

```http
PATCH /api/v1/webhooks/subscriptions/{id}
Content-Type: application/json
Authorization: Bearer ${API_KEY}

{
  "events": [
    "threatflow.ioc.ingested",
    "threatflow.correlation.match",
    "threatflow.bundle.exported"
  ],
  "active": true
}
```

### Delete a Webhook Subscription

```http
DELETE /api/v1/webhooks/subscriptions/{id}
Authorization: Bearer ${API_KEY}
```

### Test a Webhook Subscription

Sends a synthetic `test.ping` event to verify connectivity and signature verification.

```http
POST /api/v1/webhooks/subscriptions/{id}/test
Authorization: Bearer ${API_KEY}
```

**Response (200 OK):**

```json
{
  "delivery_id": "d4e5f6a7-b8c9-0123-4567-89abcdef0123",
  "status_code": 200,
  "response_time_ms": 142,
  "success": true
}
```

---

## Rate Limits

| Direction | Limit | Window |
|-----------|-------|--------|
| Inbound (per source IP) | 100 requests | 1 minute |
| Outbound (per target) | 60 requests | 1 minute |

When the inbound rate limit is exceeded, ThreatFlow responds with `429 Too Many Requests` and a `Retry-After` header indicating the number of seconds to wait.

For outbound webhooks, ThreatFlow queues excess deliveries and drains them at the rate limit. This prevents overwhelming downstream consumers during burst ingestion events (e.g., a large feed poll).

---

## Configuration Reference

```yaml
webhooks:
  inbound:
    apiguard:
      secret: "${THREATFLOW_APIGUARD_WEBHOOK_SECRET}"
      rate_limit: 100  # requests per minute
    citadel:
      secret: "${THREATFLOW_CITADEL_KEY_SECRET}"
      rate_limit: 200
    generic:
      secret: "${THREATFLOW_GENERIC_WEBHOOK_SECRET}"
      rate_limit: 50

  outbound:
    irflow:
      url: "http://irflow:8083/api/v1/webhooks/threatflow"
      secret: "${THREATFLOW_IRFLOW_WEBHOOK_SECRET}"
      events:
        - threatflow.correlation.match
        - threatflow.ioc.ingested
      retry:
        max_attempts: 4
        backoff: [30, 60, 120]  # seconds
    nis2compass:
      url: "http://nis2compass:5000/api/v1/webhooks/threatflow"
      secret: "${THREATFLOW_NIS2COMPASS_WEBHOOK_SECRET}"
      events:
        - threatflow.bundle.exported
      retry:
        max_attempts: 4
        backoff: [30, 60, 120]
    opencsirt:
      url: "http://opencsirt:8092/api/v1/advisories/import"
      secret: "${THREATFLOW_OPENCSIRT_WEBHOOK_SECRET}"
      events:
        - threatflow.bundle.exported
      retry:
        max_attempts: 4
        backoff: [30, 60, 120]

  dead_letter:
    enabled: true
    retention_days: 30
    max_items: 10000
```

---

## Event Type Reference

Complete list of event types used in ThreatFlow webhooks:

### Inbound Events (received by ThreatFlow)

| Event Type | Source | Description |
|-----------|--------|-------------|
| `apiguard.scan.completed` | APIGuard | Scan finished -- findings available for IOC extraction |
| `apiguard.finding.critical` | APIGuard | Critical finding detected -- immediate IOC extraction |
| `citadel.marshal.decision` | CITADEL | MARSHAL governance decision delivered |
| `citadel.augur.advisory` | CITADEL | AUGUR advisory published -- may block ingestion |
| `citadel.vigil.alert` | CITADEL | VIGIL monitoring alert (planned — VIGIL is design-stage as of CITADEL v1.0.0, ships v2.0) |
| `custom.ioc.report` | Third-party | Custom IOC report from external scanner |

### Outbound Events (sent by ThreatFlow)

| Event Type | Consumer(s) | Description |
|-----------|-------------|-------------|
| `threatflow.ioc.ingested` | IRFlow | New IOC persisted to store |
| `threatflow.ioc.revoked` | IRFlow | IOC expired or manually revoked |
| `threatflow.feed.polled` | (internal) | Feed poll completed -- logged to CITADEL WORM |
| `threatflow.bundle.exported` | NIS2Compass, OpenCSIRT | STIX bundle exported for downstream use |
| `threatflow.correlation.match` | IRFlow | IOC matched to active finding or incident |
| `threatflow.sighting.created` | (internal) | IOC observed in ecosystem platform |
