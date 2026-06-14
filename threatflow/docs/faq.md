# ThreatFlow FAQ

Frequently asked questions about ThreatFlow, the threat intelligence hub in the opensecstack ecosystem.

---

## General

### What is ThreatFlow and when should I use it?

ThreatFlow is an open-source threat intelligence aggregation and correlation service. It ingests indicators of compromise (IOCs) from external feeds (TAXII 2.1, CSV, MISP) and manual uploads, stores them in STIX 2.1 format, and correlates them with findings from other opensecstack platforms like APIGuard and IRFlow.

Use ThreatFlow when you need a central, STIX-native repository for IOC data that integrates with your security operations tooling and meets NIS2 compliance requirements through CITADEL governance.

### How does ThreatFlow compare to MISP?

MISP is a full-featured threat intelligence sharing platform with its own data model, taxonomies, and galaxies. ThreatFlow is narrower in scope and designed specifically for the opensecstack ecosystem:

| Aspect | ThreatFlow | MISP |
|--------|-----------|------|
| Data model | STIX 2.1 native | MISP JSON (with STIX export) |
| Governance | CITADEL MARSHAL-gated mutations, WORM audit log | Built-in sharing groups and ACLs |
| Ecosystem | Tight integration with APIGuard, IRFlow, NIS2 Compass | Standalone with broad community integrations |
| Scale target | 10K IOCs/sec ingestion at v0.5 | Varies by deployment |
| Language | Go | Python (PHP frontend) |

ThreatFlow can ingest from MISP instances -- they are complementary, not competing tools.

### Why STIX 2.1 instead of OpenIOC or custom JSON?

STIX 2.1 (Structured Threat Information Expression) is the OASIS standard for cyber threat intelligence. We chose it for three reasons:

1. **Interoperability** -- STIX 2.1 is supported by TAXII servers, MISP, OpenCTI, and most commercial threat intel platforms. Using it natively means zero-cost data exchange.
2. **Expressiveness** -- STIX 2.1 supports indicators, relationships, attack patterns (ATT&CK), sightings, and more. OpenIOC is limited to indicator definitions.
3. **NIS2 alignment** -- EU NIS2 Article 29 encourages the use of standardized formats for cyber threat intelligence sharing. STIX 2.1 is the de facto standard referenced by ENISA guidelines.

---

## Feeds and Ingestion

### How frequently should threat feeds be polled?

It depends on the feed type and your operational needs:

| Feed Type | Recommended Interval | Rationale |
|-----------|---------------------|-----------|
| TAXII 2.1 (high-fidelity) | 5--15 minutes | Near-real-time intelligence from trusted sources |
| CSV (abuse.ch, AlienVault OTX) | 1--4 hours | Bulk feeds updated periodically |
| MISP instances | 15--60 minutes | Event-based; poll frequency depends on instance activity |
| Manual uploads | N/A | On-demand via API or CLI |

Configure per-feed intervals in the `feeds` table (`poll_interval` column). Overly aggressive polling wastes bandwidth and may trigger rate limiting on the source.

### Can ThreatFlow ingest from commercial threat intel vendors?

Yes, as long as the vendor provides data in a supported format:

- **TAXII 2.1 endpoint** -- native support.
- **CSV export** -- write a parser for the vendor's CSV format (see [ioc-feeds.md](ioc-feeds.md)).
- **STIX 2.1 bundles** -- POST directly to `POST /api/v1/stix/bundles`.
- **Custom API** -- implement a new feed adapter in `internal/feed/`.

Commercial vendors like Recorded Future, Mandiant, and CrowdStrike Falcon Intel all support at least one of these formats. You are responsible for complying with the vendor's license terms regarding data storage and redistribution.

### What IOC types are supported?

ThreatFlow supports any indicator type expressible in STIX 2.1. The most common types used in practice:

| IOC Type | Example | STIX Pattern |
|----------|---------|-------------|
| `ipv4-addr` | `198.51.100.42` | `[ipv4-addr:value = '198.51.100.42']` |
| `ipv6-addr` | `2001:db8::1` | `[ipv6-addr:value = '2001:db8::1']` |
| `domain-name` | `evil.example.com` | `[domain-name:value = 'evil.example.com']` |
| `url` | `https://evil.example.com/payload` | `[url:value = '...']` |
| `file` (hash) | `sha256:abc123...` | `[file:hashes.'SHA-256' = 'abc123...']` |
| `email-addr` | `phisher@evil.com` | `[email-addr:value = 'phisher@evil.com']` |
| `mutex` | `Global\EvilMutex` | `[mutex:name = 'Global\\EvilMutex']` |

Custom types can be added by extending the validation logic in `internal/domain/ioc.go`.

### What's the retention policy for expired IOCs?

IOCs have an optional `expires_at` timestamp set by the feed source or administrator. Expired IOCs are:

1. **Excluded from active queries** -- `GET /api/v1/iocs` filters out expired IOCs by default (override with `?include_expired=true`).
2. **Retained in the database** -- expired IOCs are not deleted. They remain available for historical analysis, sighting correlation, and audit purposes.
3. **Soft-revocable** -- the `revoked` flag can be set to suppress an IOC without deleting it, following STIX 2.1 revocation semantics.

For storage management, old partitions (see [performance.md](performance.md)) can be detached and archived to cold storage.

---

## Deduplication and Scoring

### How does deduplication work?

ThreatFlow deduplicates IOCs using a SHA-256 hash of the normalized STIX pattern string, stored in the `pattern_hash` column with a unique constraint.

**Process:**

1. On ingestion, the IOC value is normalized (lowercased, trimmed, canonicalized by type).
2. A STIX 2.1 pattern string is generated (e.g., `[ipv4-addr:value = '198.51.100.42']`).
3. The SHA-256 of the pattern is computed.
4. If a row with the same `pattern_hash` exists, the existing IOC is updated (`last_seen`, `confidence`) rather than inserting a duplicate.

This means the same IP address from two different feeds produces a single IOC with an updated confidence score and the most recent sighting timestamp.

### How does confidence scoring work?

Each IOC has an integer confidence score from 0 to 100. The score is computed as:

```
confidence = feed_base_confidence * feed_accuracy_ratio * age_decay_factor
```

Where:

- **`feed_base_confidence`** -- a static score (0--100) assigned to the feed source. High-fidelity government CERTs might get 90; open community feeds might get 50.
- **`feed_accuracy_ratio`** -- a float (0.0--1.0) representing the feed's historical true-positive rate, updated over time via Bayesian scoring (planned for v0.3).
- **`age_decay_factor`** -- a multiplier that decreases as the IOC ages, configurable per feed. A 30-day-old IOC from a feed with a 7-day half-life gets a lower score than a fresh one.

When multiple feeds report the same IOC (deduplicated by `pattern_hash`), the confidence is the maximum across sources.

---

## Architecture and Integration

### How does CITADEL governance affect IOC ingestion?

Starting in v0.3, all mutation operations (IOC creation, update, revocation, feed configuration changes) are gated by CITADEL MARSHAL. The flow is:

1. ThreatFlow receives an ingestion request.
2. Before persisting, it sends an `EXECUTE` evaluation request to CITADEL MARSHAL with the action and resource details.
3. MARSHAL returns `ALLOW`, `DENY`, or `ESCALATE`.
4. On `ALLOW`, the IOC is persisted and a WORM event is logged to CITADEL.
5. On `DENY`, the request is rejected with `403 Forbidden` and the denial is logged.
6. On `ESCALATE`, the IOC is queued for human review.

This ensures full auditability and policy enforcement for all threat intelligence data.

### What happens if CITADEL is down?

ThreatFlow's behavior when CITADEL is unreachable depends on configuration:

| Mode | Behavior | Config |
|------|----------|--------|
| **Enforce** (default) | Mutations fail with `503 Service Unavailable`. Reads continue normally. | `THREATFLOW_CITADEL_MODE=enforce` |
| **Warn** | Mutations proceed but are flagged as unaudited. A warning is logged. | `THREATFLOW_CITADEL_MODE=warn` |
| **Disabled** | CITADEL integration is off. No governance checks or WORM logging. | `THREATFLOW_CITADEL_API_URL` unset |

In production, **enforce** mode is strongly recommended. Design your deployment so that CITADEL and ThreatFlow share the same availability tier.

### Can I use ThreatFlow standalone without other opensecstack platforms?

Yes. ThreatFlow only requires PostgreSQL. All ecosystem integrations (CITADEL, APIGuard, IRFlow, NIS2 Compass) are optional and configured via environment variables. If the integration URL is unset, the feature is disabled.

A standalone ThreatFlow instance is useful as a lightweight IOC repository with STIX 2.1 support, feed aggregation, and a REST API.

---

## Data Management

### How do I add my own custom feed source?

There are two approaches depending on the data format:

**Option A: Push via API**

If your source can make HTTP calls, push IOCs directly:

```bash
curl -X POST http://localhost:8091/api/v1/iocs \
    -H "Content-Type: application/json" \
    -d '{"type":"domain-name","value":"evil.example.com","source":"my-feed","confidence":75}'
```

Or push a STIX 2.1 bundle:

```bash
curl -X POST http://localhost:8091/api/v1/stix/bundles \
    -H "Content-Type: application/json" \
    -d @my_bundle.json
```

**Option B: Write a feed adapter**

For scheduled polling, implement the `FeedPoller` interface in `internal/feed/`:

```go
type FeedPoller interface {
    Poll(ctx context.Context) ([]domain.IOC, error)
    Name() string
}
```

Register the adapter in `internal/feed/registry.go` and configure it via the `feeds` table. See [ioc-feeds.md](ioc-feeds.md) for the full guide.

### What's the maximum IOC capacity?

There is no hard-coded limit. Practical capacity depends on your PostgreSQL sizing:

| Deployment | Estimated Capacity | Notes |
|------------|-------------------|-------|
| Minimal (2 CPU, 4GB) | ~50K IOCs | Suitable for evaluation and small teams |
| Standard (4 CPU, 8GB) | ~500K IOCs | Handles most mid-size organizations |
| Production (8 CPU, 32GB) | ~5M IOCs | Table partitioning recommended above 1M |
| Large (16 CPU, 64GB) | ~50M IOCs | Partitioning required; read replicas recommended |

See [performance.md](performance.md) for detailed scaling guidance and table partitioning instructions.

### How do I export data from ThreatFlow?

ThreatFlow supports several export methods:

- **STIX 2.1 bundles** -- `GET /api/v1/stix/bundles` returns pre-built bundles. Planned: filtered export with query parameters.
- **IOC list** -- `GET /api/v1/iocs` with pagination and filtering. Supports JSON responses.
- **Bulk export (planned v0.4)** -- `GET /api/v1/export` with content negotiation for STIX 2.1 JSON, CSV, or MISP JSON format.
- **CLI** -- `threatflow ioc export --format stix --filter "type=ipv4-addr"` (planned).

All exports respect CITADEL governance -- export operations are logged as WORM events.

---

## Troubleshooting

### The service starts but IOC ingestion returns 500 errors

Check the following in order:

1. **Database connectivity** -- verify `THREATFLOW_DB_URL` is correct and the database is reachable.
2. **Migrations** -- ensure all migrations have been applied: `threatflow migrate up`.
3. **Logs** -- check the structured JSON logs for the specific error. Set `THREATFLOW_LOG_LEVEL=debug` for more detail.
4. **CITADEL** -- if `THREATFLOW_CITADEL_API_URL` is set but CITADEL is unreachable, mutations will fail in enforce mode.

### Feed polling is not picking up new IOCs

1. Verify the feed is enabled: check the `enabled` column in the `feeds` table.
2. Check `error_count` -- if it is high, the feed endpoint may be unreachable or returning errors.
3. Review `last_poll_at` -- if it is null or very old, the poller may not be running.
4. Ensure only one pod is polling each feed (see leader election in [performance.md](performance.md)).

### Memory usage grows over time

ThreatFlow is written in Go with garbage collection, so steady-state memory should be stable. If usage grows:

1. Check for unclosed response bodies in feed pollers.
2. Large STIX bundles (>10MB) may cause transient spikes -- ensure `THREATFLOW_MAX_BODY_SIZE` is set.
3. Monitor goroutine count: expose `runtime.NumGoroutine()` via the health endpoint or metrics.
4. Profile with `go tool pprof` against the debug endpoint if enabled.

See [troubleshooting.md](troubleshooting.md) for additional diagnostics.
