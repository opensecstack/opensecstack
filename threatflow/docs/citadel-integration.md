# CITADEL Integration

ThreatFlow integrates with CITADEL for governance (MARSHAL decision gating) and auditability (WORM chain logging). All mutation operations are WORM-logged, and high-impact operations are MARSHAL-gated.

---

## Authentication

ThreatFlow authenticates to CITADEL as a **connector** using HMAC-SHA256:

| Header | Value |
|--------|-------|
| `X-CITADEL-KEY` | Connector key ID (from `THREATFLOW_CITADEL_KEY_ID`) |
| `X-CITADEL-TS` | Unix timestamp |
| `X-CITADEL-SIG` | `hmac-sha256=<hex(HMAC(secret, key_id:ts:sha256(body)))>` |

The shared secret is configured via `THREATFLOW_CITADEL_KEY_SECRET`.

---

## WORM Events

ThreatFlow emits the following events to the CITADEL WORM chain:

| Event Type | Trigger | Payload |
|-----------|---------|---------|
| `threatflow.ioc.ingested` | New IOC persisted | IOC ID, type, value, source, confidence |
| `threatflow.ioc.updated` | IOC metadata changed | IOC ID, changed fields |
| `threatflow.ioc.revoked` | IOC marked as revoked/expired | IOC ID, reason |
| `threatflow.feed.polled` | Successful feed poll | Feed name, new IOC count, duration |
| `threatflow.feed.error` | Feed poll failure | Feed name, error message, attempt count |
| `threatflow.bundle.imported` | STIX bundle ingested | Bundle ID, object count, source |
| `threatflow.bundle.exported` | STIX bundle exported | Bundle ID, object count, consumer |
| `threatflow.sighting.created` | IOC observed in ecosystem | IOC ID, platform, resource ID |
| `threatflow.correlation.match` | Cross-feed correlation hit | IOC IDs, confidence, relationship type |

### Event Format

```json
{
  "source": "threatflow",
  "event_type": "threatflow.ioc.ingested",
  "project_id": "threatflow",
  "payload": {
    "ioc_id": "ioc-550e8400...",
    "type": "ipv4-addr",
    "value": "198.51.100.42",
    "source": "alienvault-otx",
    "confidence": 85,
    "stix_id": "indicator--abc123",
    "ttp": ["T1071.001"]
  }
}
```

---

## MARSHAL Gating

High-impact operations require a MARSHAL EXECUTE decision before proceeding:

| Operation | MARSHAL Action Type | Why |
|-----------|-------------------|-----|
| Bulk feed ingestion (> 100 IOCs) | `bulk_ioc_ingest` | Prevent accidental mass pollution of IOC store |
| Feed source addition | `feed_source_add` | New feeds should be reviewed before activation |
| STIX bundle export to external consumer | `stix_export` | Outbound intelligence sharing is a policy decision |
| IOC confidence override (manual) | `ioc_confidence_override` | Manual overrides bypass automated scoring |

### Kerkese Example

```json
{
  "kerkese_version": "1.0",
  "project_id": "threatflow",
  "execution_id": "poll-otx-2026-03-31",
  "action": {
    "type": "bulk_ioc_ingest",
    "label": "Ingest 247 IOCs from alienvault-otx feed"
  },
  "actor": {
    "user_id": 0,
    "role": "group_sig_operator"
  },
  "evidence": {
    "feed_name": "alienvault-otx",
    "ioc_count": 247,
    "confidence_base": 70
  },
  "sod": {
    "operator_user_id": 0,
    "verifier_user_id": 0
  },
  "dry_run": false
}
```

If MARSHAL returns **REFUSE**, the IOCs are not persisted and the feed poll is logged as rejected. If **HARD_STOP**, ThreatFlow pauses the feed and raises a VIGIL RED alert.

---

## Disabled Mode

When `THREATFLOW_CITADEL_API_URL` is empty, all CITADEL calls are no-ops:
- WORM events are silently discarded
- MARSHAL evaluations return implicit EXECUTE
- IOC operations proceed without governance checks

This mode is intended for local development and testing only.

---

## See Also

- [IOC Feeds](ioc-feeds.md) — MARSHAL gating for feed ingestion
- [Architecture](architecture.md) — governance layer in the system design
- [API Reference](api-reference.md) — 403 responses when MARSHAL refuses
- [Configuration](configuration.md) — CITADEL environment variables
- [Security Model](security-model.md) — L4 application security controls via MARSHAL
- [Troubleshooting](troubleshooting.md) — debugging CITADEL connectivity issues
