# ThreatFlow Integration Guide

ThreatFlow is the threat intelligence hub connecting all opensecstack platforms. It ingests IOCs from external feeds and internal scan results, correlates them across the ecosystem, and distributes enriched STIX 2.1 intelligence to incident responders, compliance assessors, and advisory publishers.

This document covers every integration point: inbound data flows, outbound enrichment, governance hooks, and SDK usage.

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ThreatFlow (:8091)                       │
│                                                             │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Ingestion│  │ Correlation│  │  Export   │  │ Feed Mgmt│ │
│  │  Engine  │  │   Engine   │  │  Engine   │  │          │ │
│  └────┬─────┘  └─────┬──────┘  └────┬─────┘  └────┬─────┘ │
└───────┼──────────────┼──────────────┼──────────────┼───────┘
        │              │              │              │
  ┌─────▼──────┐  ┌───▼────┐  ┌─────▼──────┐  ┌───▼──────┐
  │  APIGuard  │  │ IRFlow │  │NIS2Compass │  │  TAXII   │
  │  Findings  │  │Incidents│  │  Evidence  │  │  Feeds   │
  └────────────┘  └────────┘  └────────────┘  └──────────┘
```

### Data Exchange Format

All intelligence data is exchanged using **STIX 2.1** (Structured Threat Information Expression). See [stix-integration.md](stix-integration.md) for object types, bundle format, and TAXII polling details.

### Port Assignments

| Platform | Default Port | Role |
|----------|-------------|------|
| APIGuard | `:8080` | Scan findings source |
| IRFlow | `:8083` | Incident enrichment consumer |
| NIS2Compass | `:5000` | Compliance evidence consumer |
| CITADEL | `:8099` | Governance and audit |
| ThreatFlow | `:8091` | Intelligence hub (this service) |
| OpenCSIRT | `:8092` | Advisory generation consumer |

---

## APIGuard to ThreatFlow

### Trigger: Scan Completed or Critical Finding Detected

When APIGuard completes a scan, it emits `apiguard.scan.completed` events to CITADEL. When a scan produces CRITICAL findings, APIGuard also emits `apiguard.finding.critical`. ThreatFlow subscribes to both event types and can:

1. Extract IOCs from the finding (endpoint URLs, IPs, domains in scan targets)
2. Cross-reference extracted indicators against known threat intelligence
3. Enrich the finding with ATT&CK TTPs from matching IOCs
4. Publish enriched context back to IRFlow for incident correlation

### Configuration

```yaml
integrations:
  apiguard:
    url: "http://apiguard:8080"
    api_key: "${THREATFLOW_APIGUARD_API_KEY}"
    webhook_secret: "${THREATFLOW_APIGUARD_WEBHOOK_SECRET}"
    events:
      - apiguard.scan.completed
      - apiguard.finding.critical
    ioc_extraction:
      enabled: true
      types:
        - ipv4-addr
        - domain-name
        - url
```

### API Flow

```
APIGuard                    ThreatFlow                    CITADEL
   │                            │                            │
   ├─ scan.completed event ─────►                            │
   │                            ├─ Extract IOCs              │
   │                            ├─ Query existing IOC store  │
   │                            ├─ MARSHAL evaluate ─────────►
   │                            │◄──── EXECUTE ──────────────┤
   │                            ├─ Store new IOCs            │
   │                            ├─ WORM log ─────────────────►
   │                            │                            │
   │◄── enriched findings ──────┤                            │
```

### Inbound Webhook: Receive Scan Result

ThreatFlow exposes a webhook endpoint for APIGuard events. APIGuard sends scan results as they complete, and ThreatFlow extracts IOCs from the scan target metadata.

```http
POST /api/v1/webhooks/apiguard
Content-Type: application/json
X-ThreatFlow-Signature: sha256=<hmac-sha256-hex-digest>
X-ThreatFlow-Timestamp: 1743379200

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

### IOC Extraction Rules

ThreatFlow applies the following extraction rules to APIGuard findings:

| Finding Field | Extracted IOC Type | STIX SCO |
|--------------|-------------------|----------|
| `target_ip` | IP address | `ipv4-addr` or `ipv6-addr` |
| `target_domain` | Domain | `domain-name` |
| `endpoint_path` (with host) | URL | `url` |
| `response_headers.Location` | URL | `url` |
| `request_body` (hashes) | File hash | `file` |

Each extracted IOC is stored as a STIX Indicator with a `sighting` relationship back to the APIGuard finding.

---

## ThreatFlow to IRFlow

### Trigger: IOC Enrichment Request During Incident

When IRFlow handles an incident and a playbook requests IOC enrichment, IRFlow calls ThreatFlow to provide STIX 2.1 bundles with relevant IOCs. This can happen automatically (via playbook execution) or manually (analyst-triggered enrichment).

### IRFlow Playbook Integration

From `irflow/examples/playbook_critical_finding.yaml`, the enrichment step:

```yaml
- id: enrich_iocs
  name: Enrich with Threat Intelligence
  type: enrich
  config:
    sources:
      - threatflow
    ioc_types:
      - ip
      - domain
  on_success: contain_endpoint
```

When this step executes, IRFlow calls ThreatFlow's enrichment endpoint with the incident context.

### Enrichment Request (IRFlow to ThreatFlow)

```http
POST /api/v1/enrich
Content-Type: application/json
Authorization: Bearer ${IRFLOW_THREATFLOW_API_KEY}

{
  "incident_id": "inc-20260331-001",
  "indicators": [
    { "type": "ipv4-addr", "value": "198.51.100.42" },
    { "type": "domain-name", "value": "evil.example.com" }
  ],
  "confidence_min": 50,
  "include_relationships": true
}
```

**Response (200 OK):**

```json
{
  "incident_id": "inc-20260331-001",
  "bundle_id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "matches": 2,
  "iocs": [
    {
      "stix_id": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
      "type": "ipv4-addr",
      "value": "198.51.100.42",
      "confidence": 85,
      "ttp": ["T1071.001"],
      "source": "alienvault-otx",
      "first_seen": "2026-03-15T10:00:00Z",
      "last_seen": "2026-03-30T14:22:00Z",
      "related_campaigns": ["APT-Example-2026Q1"]
    },
    {
      "stix_id": "indicator--aabbccdd-eeff-0011-2233-445566778899",
      "type": "domain-name",
      "value": "evil.example.com",
      "confidence": 92,
      "ttp": ["T1566.002", "T1071.001"],
      "source": "internal-misp",
      "first_seen": "2026-02-28T08:00:00Z",
      "last_seen": "2026-03-31T09:15:00Z",
      "related_malware": ["ExampleRAT"]
    }
  ]
}
```

### Outbound Webhook: Push IOC Context to IRFlow

When ThreatFlow discovers a correlation match for an active incident, it proactively pushes an update to IRFlow via webhook. See the [IRFlow webhook spec](../../irflow/docs/api.md) for `POST /api/v1/webhooks/threatflow`.

```http
POST http://irflow:8083/api/v1/webhooks/threatflow
Content-Type: application/json
X-ThreatFlow-Signature: sha256=<hmac-sha256-hex-digest>
X-ThreatFlow-Timestamp: 1743379200

{
  "event_type": "threatflow.correlation.match",
  "incident_id": "inc-20260331-001",
  "bundle_id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "iocs": [
    {
      "type": "ipv4-addr",
      "value": "198.51.100.42",
      "confidence": 85,
      "ttp": ["T1071.001"],
      "source": "alienvault-otx",
      "first_seen": "2026-03-15T10:00:00Z"
    }
  ],
  "stix_bundle_url": "http://threatflow:8091/api/v1/stix/bundles/bundle--a1b2c3d4"
}
```

### Configuration

```yaml
integrations:
  irflow:
    url: "http://irflow:8083"
    webhook_secret: "${THREATFLOW_IRFLOW_WEBHOOK_SECRET}"
    api_key: "${THREATFLOW_IRFLOW_API_KEY}"
    push_events:
      - threatflow.correlation.match
      - threatflow.ioc.ingested
    enrichment:
      confidence_min: 50
      max_results: 100
```

---

## ThreatFlow to NIS2Compass

### Supply Chain Evidence (Article 21(2)(d))

ThreatFlow provides IOC data as compliance evidence for NIS2 supply chain security assessments. Under Article 21(2)(d), essential and important entities must address supply chain security -- ThreatFlow's intelligence on third-party infrastructure and supply chain compromise IOCs directly supports these controls.

### Integration Flow

1. NIS2Compass assessment identifies a supply chain control gap (Article 21(2)(d))
2. Assessor requests IOC evidence from ThreatFlow for the assessment period
3. ThreatFlow exports a filtered STIX 2.1 bundle containing supply chain related IOCs
4. Bundle is uploaded as an evidence artifact to the NIS2Compass assessment

### Export Supply Chain IOCs

```http
GET /api/v1/stix/bundles/export?tags=supply-chain&since=2026-01-01&until=2026-03-31&format=stix21&confidence_min=70
Accept: application/stix+json;version=2.1
Authorization: Bearer ${NIS2COMPASS_THREATFLOW_API_KEY}
```

**Response (200 OK):**

```json
{
  "type": "bundle",
  "id": "bundle--f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
      "created": "2026-02-10T08:00:00Z",
      "modified": "2026-03-15T12:00:00Z",
      "name": "Supply chain compromise IP",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "pattern_type": "stix",
      "valid_from": "2026-02-10T08:00:00Z",
      "confidence": 85,
      "labels": ["supply-chain", "malicious-activity"]
    }
  ]
}
```

### Upload to NIS2Compass

```http
POST http://nis2compass:5000/api/v1/assessments/{assessment_id}/artifacts
Content-Type: multipart/form-data
Authorization: Bearer ${NIS2COMPASS_API_KEY}

file=@supply-chain-iocs.json
artifact_type=evidence
control_id=art21_d
description="ThreatFlow supply chain IOC report Q1 2026"
source=threatflow
```

### Configuration

```yaml
integrations:
  nis2compass:
    url: "http://nis2compass:5000"
    api_key: "${THREATFLOW_NIS2COMPASS_API_KEY}"
    export:
      default_tags:
        - supply-chain
      confidence_min: 70
      format: stix21
```

---

## ThreatFlow and CITADEL

ThreatFlow integrates with CITADEL for governance (MARSHAL decision gating) and auditability (WORM chain-hashed logging). See [citadel-integration.md](citadel-integration.md) for the full specification.

### Authentication

ThreatFlow authenticates to CITADEL as a **connector** using HMAC-SHA256:

| Header | Value |
|--------|-------|
| `X-CITADEL-KEY` | Connector key ID (`THREATFLOW_CITADEL_KEY_ID`) |
| `X-CITADEL-TS` | Unix timestamp (seconds) |
| `X-CITADEL-SIG` | `hmac-sha256=<hex(HMAC(secret, key_id:ts:sha256(body)))>` |

### MARSHAL Governance

Every mutation is evaluated by MARSHAL before it proceeds:

| Operation | MARSHAL Action Type |
|-----------|-------------------|
| IOC ingest (`POST /api/v1/iocs`) | `IOC_INGEST` |
| STIX bundle import (`POST /api/v1/stix/bundles`) | `STIX_BUNDLE_IMPORT` |
| Feed create (`POST /api/v1/feeds`) | `FEED_CREATE` |
| Feed enable/disable (`PATCH /api/v1/feeds/{id}`) | `FEED_TOGGLE` |
| Feed delete (`DELETE /api/v1/feeds/{id}`) | `FEED_DELETE` |

If MARSHAL returns **REFUSE** or **HARD_STOP**, the request is rejected with
HTTP 403 and not persisted.

The Kerkese carries the caller's real identity (sinauth UUID, or the
API-key/bootstrap fallback subject) as `actor`, plus a fixed placeholder
`verifier` (`threatflow-system-verifier`) — ThreatFlow has no second-approver
concept for any governed action today, so governance runs single-party. See
[CITADEL Integration — Actor identity / Verifier](citadel-integration.md#actor-identity)
for the full explanation of why the placeholder is used and why it's safe.

### WORM Events

All operations are logged to the CITADEL WORM immutable audit trail:

| Event | When | Payload |
|-------|------|---------|
| `threatflow.ioc.ingested` | New IOC persisted | IOC ID, type, value, source, confidence |
| `threatflow.ioc.updated` | IOC metadata changed | IOC ID, changed fields |
| `threatflow.ioc.revoked` | IOC marked as revoked/expired | IOC ID, reason |
| `threatflow.feed.polled` | Feed poll completed | Feed name, IOCs added/updated/skipped |
| `threatflow.feed.error` | Feed poll failure | Feed name, error message, attempt count |
| `threatflow.bundle.imported` | STIX bundle ingested | Bundle ID, object count, source |
| `threatflow.bundle.exported` | STIX bundle exported | Bundle ID, recipient, IOC count |
| `threatflow.sighting.created` | IOC observed in ecosystem | IOC ID, platform, resource ID |
| `threatflow.correlation.match` | IOC matched to finding/incident | IOC IDs, confidence, relationship type |

### CITADEL Event Format

```json
{
  "source": "threatflow",
  "event_type": "threatflow.ioc.ingested",
  "project_id": "threatflow",
  "payload": {
    "ioc_id": "ioc-550e8400-e29b-41d4-a716-446655440000",
    "type": "ipv4-addr",
    "value": "198.51.100.42",
    "source": "alienvault-otx",
    "confidence": 85,
    "stix_id": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
    "ttp": ["T1071.001"]
  }
}
```

### AUGUR Advisory Gate

CITADEL AUGUR advisories can block IOC ingestion at Gate 4 (pre-persist). When an AUGUR advisory flags a feed source as unreliable or a specific IOC pattern as a known false positive, MARSHAL automatically refuses the ingestion.

### Configuration

```yaml
integrations:
  citadel:
    url: "${THREATFLOW_CITADEL_API_URL}"
    key_id: "${THREATFLOW_CITADEL_KEY_ID}"
    key_secret: "${THREATFLOW_CITADEL_KEY_SECRET}"
    worm:
      enabled: true
      batch_size: 50
      flush_interval: 5s
    marshal:
      enabled: true
      timeout: 10s
```

### Disabled Mode

When `THREATFLOW_CITADEL_API_URL` is empty, all CITADEL calls are no-ops:
- WORM events are silently discarded
- MARSHAL evaluations return implicit EXECUTE
- IOC operations proceed without governance checks

This mode is intended for local development and testing only.

---

## ThreatFlow to OpenCSIRT

### Advisory Generation

ThreatFlow provides STIX 2.1 bundles to OpenCSIRT for cross-organizational advisory publication. When ThreatFlow detects a cluster of related IOCs that warrant a public advisory, it can push a curated STIX bundle to OpenCSIRT for CSAF 2.0 advisory generation.

### Planned Integration (v0.4+)

```http
POST http://opencsirt:8092/api/v1/advisories/import
Content-Type: application/stix+json;version=2.1
Authorization: Bearer ${OPENCSIRT_API_KEY}
X-ThreatFlow-Signature: sha256=<hmac-sha256-hex-digest>

{
  "type": "bundle",
  "id": "bundle--d4e5f6a7-b8c9-0123-4567-89abcdef0123",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
      "created": "2026-03-15T10:00:00Z",
      "modified": "2026-03-31T10:00:00Z",
      "name": "C2 callback IP for ExampleRAT campaign",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "pattern_type": "stix",
      "valid_from": "2026-03-15T10:00:00Z",
      "confidence": 92,
      "labels": ["malicious-activity", "c2"]
    },
    {
      "type": "relationship",
      "id": "relationship--aabb1122-3344-5566-7788-99aabbccddee",
      "relationship_type": "indicates",
      "source_ref": "indicator--11223344-5566-7788-99aa-bbccddeeff00",
      "target_ref": "malware--ffeeddcc-bbaa-9988-7766-554433221100"
    }
  ]
}
```

**Response (202 Accepted):**

```json
{
  "advisory_draft_id": "adv-draft-001",
  "status": "pending_review",
  "iocs_imported": 1,
  "relationships_imported": 1
}
```

### Reverse Flow: CSAF Advisories to ThreatFlow

This is a **push**, not a poll: when an OpenCSIRT advisory transitions to
`published`, OpenCSIRT's `(*ThreatFlowClient).PushAdvisory`
(`opencsirt/internal/integrations/threatflow.go`) immediately POSTs the
full CSAF 2.0 document to ThreatFlow — there is no ThreatFlow-side poller
or `advisory_import.poll_interval` config. (An earlier revision of this
document described the opposite — a ThreatFlow-side poll — which never
matched what either platform actually implemented; see
`threatflow/adrs/004-opencsirt-advisory-ingestion-gap.md` for how that
was reconciled.)

```http
POST http://threatflow:8091/api/v1/advisories?source=opencsirt
Content-Type: application/json
Authorization: Bearer <token>

{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Example RCE in Widget",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {
      "id": "OPENCSIRT-20260101-abcd1234",
      "initial_release_date": "2026-01-01T00:00:00Z",
      "current_release_date": "2026-01-01T00:00:00Z",
      "status": "final",
      "version": "1"
    },
    "distribution": {"tlp": {"label": "AMBER"}}
  },
  "product_tree": {
    "full_product_names": [{"product_id": "CSAFPID-1", "name": "Widget 1.0"}]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-00001",
      "title": "CVE-2026-00001 — Example RCE in Widget",
      "remediations": [{"category": "vendor_fix", "details": "Upgrade to 1.1", "product_ids": ["CSAFPID-1"]}]
    }
  ]
}
```

**Response (201 Created — new advisory; 200 — revision update or
idempotent duplicate; 409 — a newer revision is already stored; 400 —
malformed CSAF):**

```json
{
  "advisory_id": "5b6e...-uuid",
  "tracking_id": "OPENCSIRT-20260101-abcd1234",
  "revision": "1",
  "action": "created",
  "vulnerabilities_mapped": 1,
  "products_mapped": 1
}
```

Server-side, `POST /api/v1/advisories` (`internal/api/handlers/advisory.go`,
`internal/csaf`) maps every `vulnerabilities[]` entry onto a STIX 2.1
`vulnerability` object — ThreatFlow's canonical representation for CVE
data, per `threatflow/adrs/001-stix-21-as-canonical-format.md` — and keeps
`product_tree` / `remediations[]` (which have no STIX 2.1 equivalent) in
dedicated `advisory_*` tables (migration 009) cross-referenced to that
STIX object. The dedup/revision key is
`document.tracking.id` + `document.tracking.version`: a new version
replaces the current advisory's vulnerability/product set; a repeat of an
already-seen version is a no-op; an out-of-order older version is
rejected without touching current state. Auth matches every other
ThreatFlow mutation endpoint (`Authorization: Bearer <JWT>`, operator role
required, obtained via `POST /api/v1/auth/token`) — see the ADR-004
implementation note for the known gap between that contract and what
OpenCSIRT's client currently sends.

### Configuration

```yaml
integrations:
  opencsirt:
    url: "http://opencsirt:8092"
    api_key: "${THREATFLOW_OPENCSIRT_API_KEY}"
    push_events:
      - threatflow.bundle.exported
```

---

## SDK Integration Examples

All opensecstack platforms communicate through the shared SDK. The SDK provides typed clients for CITADEL event publishing, webhook routing, and cross-platform calls. See the [SDK README](../../sdk/README.md) for the full language matrix.

### Go SDK

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/opensecstack/opensecstack/sdk/go/opensecstack"
)

func main() {
    ctx := context.Background()

    // Connect to CITADEL for ThreatFlow events
    citadel := opensecstack.NewCITADELClient(opensecstack.CITADELClientOptions{
        BaseURL:      "http://localhost:8099",
        SharedSecret: os.Getenv("CITADEL_SECRET"),
    })

    // Retrieve recent IOC ingestion events
    events, err := citadel.GetEvents(ctx, &opensecstack.GetEventsOptions{
        Source:    "threatflow",
        EventType: "threatflow.ioc.ingested",
        Limit:    100,
    })
    if err != nil {
        panic(err)
    }

    for _, event := range events {
        fmt.Printf("IOC ingested: %s (confidence: %d)\n",
            event.Payload["value"], event.Payload["confidence"])
    }

    // Publish a sighting event when an IOC is observed
    err = citadel.PublishEvent(ctx, &opensecstack.Event{
        Source:    "threatflow",
        EventType: "threatflow.sighting.created",
        ProjectID: "threatflow",
        Payload: map[string]interface{}{
            "ioc_id":    "ioc-550e8400",
            "platform":  "apiguard",
            "resource_id": "finding-456",
        },
    })
    if err != nil {
        panic(err)
    }
}
```

### Python SDK

```python
import os
from opensecstack import CITADELClient

citadel = CITADELClient(
    base_url="http://localhost:8099",
    shared_secret=os.environ["CITADEL_SECRET"],
)

# Retrieve correlation match events
events = citadel.get_events(
    source="threatflow",
    event_type="threatflow.correlation.match",
    limit=50,
)

for event in events:
    print(f"Correlation match: IOCs {event.payload['ioc_ids']} "
          f"(confidence: {event.payload['confidence']})")

# Publish a bundle export event
citadel.publish_event(
    source="threatflow",
    event_type="threatflow.bundle.exported",
    project_id="threatflow",
    payload={
        "bundle_id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "consumer": "opencsirt",
        "ioc_count": 15,
    },
)
```

### TypeScript SDK

```typescript
import { CITADELClient } from "@opensecstack/sdk";

const citadel = new CITADELClient({
    baseURL: "http://localhost:8099",
    keyID: process.env.CITADEL_KEY_ID!,
    sharedSecret: process.env.CITADEL_SECRET!,
});

// Retrieve IOC ingestion events
const events = await citadel.getEvents({
    source: "threatflow",
    event_type: "threatflow.ioc.ingested",
    limit: 100,
});

for (const event of events) {
    console.log(`IOC ingested: ${event.payload.value} `
        + `(confidence: ${event.payload.confidence})`);
}

// Publish a feed poll event
await citadel.publishEvent({
    source: "threatflow",
    eventType: "threatflow.feed.polled",
    projectId: "threatflow",
    payload: {
        feed_name: "alienvault-otx",
        iocs_added: 12,
        iocs_updated: 3,
        iocs_skipped: 85,
    },
});
```

---

## Authentication Summary

| Integration | Auth Method | Direction |
|------------|------------|-----------|
| APIGuard to ThreatFlow | Webhook HMAC-SHA256 | Inbound |
| ThreatFlow to IRFlow | Webhook HMAC-SHA256 | Outbound |
| IRFlow to ThreatFlow | API key Bearer token | Inbound |
| ThreatFlow to NIS2Compass | API key Bearer token | Outbound |
| ThreatFlow to CITADEL | HMAC-SHA256 connector auth | Bidirectional |
| ThreatFlow to OpenCSIRT | API key Bearer token | Outbound |
| TAXII feeds to ThreatFlow | HTTP Basic or API key | Inbound |

All webhook signatures use the format documented in [webhook-spec.md](webhook-spec.md).

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `THREATFLOW_APIGUARD_API_KEY` | No | API key for calling APIGuard endpoints |
| `THREATFLOW_APIGUARD_WEBHOOK_SECRET` | No | HMAC secret for verifying APIGuard webhooks |
| `THREATFLOW_IRFLOW_API_KEY` | No | API key for calling IRFlow endpoints |
| `THREATFLOW_IRFLOW_WEBHOOK_SECRET` | No | HMAC secret for signing webhooks to IRFlow |
| `THREATFLOW_NIS2COMPASS_API_KEY` | No | API key for calling NIS2Compass endpoints |
| `THREATFLOW_OPENCSIRT_API_KEY` | No | API key for calling OpenCSIRT endpoints |
| `THREATFLOW_CITADEL_API_URL` | No | CITADEL base URL (empty = disabled) |
| `THREATFLOW_CITADEL_KEY_ID` | No | CITADEL connector key ID |
| `THREATFLOW_CITADEL_KEY_SECRET` | No | CITADEL connector HMAC secret |

All integration environment variables are optional. When a variable is empty or unset, the corresponding integration is disabled and calls are no-ops.

---

## Troubleshooting

### APIGuard webhooks not arriving

1. Verify `THREATFLOW_APIGUARD_WEBHOOK_SECRET` matches the secret configured in APIGuard
2. Check that ThreatFlow is reachable from APIGuard at `http://threatflow:8091/api/v1/webhooks/apiguard`
3. Inspect ThreatFlow logs for signature verification failures: `grep "webhook signature mismatch" /var/log/threatflow.log`

### IRFlow enrichment returning empty results

1. Confirm IOCs exist in ThreatFlow: `GET /api/v1/iocs?type=ipv4-addr&value=198.51.100.42`
2. Check that the `confidence_min` threshold in the enrichment request is not too high
3. Verify that the IOCs have not expired (default TTLs in [ioc-feeds.md](ioc-feeds.md))

### CITADEL MARSHAL refusing operations

1. Check the MARSHAL rejection reason in the CITADEL audit log
2. Verify the actor role has permission for the action type
3. Review AUGUR advisories that may be blocking the operation
4. See [citadel-integration.md](citadel-integration.md) for the full MARSHAL gating specification

### STIX bundle export fails

1. Verify the export parameters produce results: `GET /api/v1/iocs?tags=supply-chain&since=2026-01-01`
2. Check that MARSHAL allows `stix_export` actions for the target consumer
3. Ensure the `Accept` header is `application/stix+json;version=2.1`
