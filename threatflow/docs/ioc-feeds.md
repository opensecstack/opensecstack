# IOC Feed Management

ThreatFlow ingests Indicators of Compromise (IOCs) from multiple external and internal sources. This document covers feed configuration, the ingestion pipeline, deduplication, and confidence scoring.

---

## Supported IOC Types

| IOC Type | STIX SCO | Example |
|----------|----------|---------|
| IPv4 address | `ipv4-addr` | `198.51.100.42` |
| IPv6 address | `ipv6-addr` | `2001:db8::1` |
| Domain | `domain-name` | `evil.example.com` |
| URL | `url` | `https://evil.example.com/payload.exe` |
| File hash (SHA-256) | `file` | `e3b0c44298fc1c149afbf4c8996fb924...` |
| File hash (MD5) | `file` | `d41d8cd98f00b204e9800998ecf8427e` |
| Email address | `email-addr` | `phisher@example.com` |
| AS number | `autonomous-system` | `AS12345` |

---

## Ingestion Pipeline

```
Feed Source → Download → Parse → Normalise → Deduplicate → Score → Persist → WORM Log
```

### Stage Details

1. **Download** — HTTP(S) GET or TAXII 2.1 poll with authentication
2. **Parse** — extract IOCs from the source format (STIX JSON, CSV, MISP)
3. **Normalise** — convert to internal STIX 2.1 Indicator objects with standard patterns
4. **Deduplicate** — SHA-256(indicator.pattern) checked against existing store
5. **Score** — confidence = `feed.confidence_base * feed.accuracy_ratio`
6. **Persist** — INSERT into PostgreSQL with feed metadata, timestamps, and STIX ID
7. **WORM Log** — emit `threatflow.ioc.ingested` event to CITADEL

### CITADEL Governance

When CITADEL integration is enabled, step 6 (Persist) is gated by a MARSHAL evaluation:

```json
{
  "action": { "type": "ioc_ingest", "label": "Ingest IOC from feed" },
  "actor": { "user_id": 0, "role": "group_sig_operator" },
  "evidence": { "feed_name": "alienvault-otx", "ioc_count": 150 }
}
```

MARSHAL can **REFUSE** ingestion if the feed source is untrusted or the ingestion volume exceeds configured thresholds.

---

## Deduplication

IOCs are deduplicated using a two-layer approach:

### Layer 1: Exact Match
- SHA-256 of the normalised STIX pattern string
- Identical indicators from different feeds are merged — confidence is updated to the maximum

### Layer 2: Fuzzy Match (planned)
- Domain similarity: `evil.example.com` and `evil.example.co` flagged as related
- IP range overlap: `198.51.100.0/24` subsumes `198.51.100.42`
- URL path similarity: same domain + similar path structure

---

## Confidence Scoring

Each IOC carries a confidence score from 0 to 100:

| Score | Meaning |
|-------|---------|
| 90–100 | High confidence — verified by multiple sources or manual analysis |
| 70–89 | Medium confidence — from a trusted feed with good accuracy history |
| 50–69 | Low confidence — from a new or less-reliable feed |
| 0–49 | Very low — unverified, single-source, or aged indicators |

### Scoring Formula

```
confidence = feed.confidence_base * feed.accuracy_ratio * age_decay_factor
```

- **confidence_base** — set per feed in configuration (e.g. 70 for OTX, 90 for internal MISP)
- **accuracy_ratio** — historical true-positive rate for this feed (starts at 1.0)
- **age_decay_factor** — `exp(-0.01 * days_since_first_seen)` — IOCs lose confidence over time

---

## IOC Expiry

IOCs have a configurable TTL:

| Feed Type | Default TTL |
|-----------|-------------|
| Manual | 90 days |
| TAXII 2.1 | 60 days |
| CSV | 30 days |
| MISP | Uses MISP event expiry |

Expired IOCs are not deleted — they are marked `revoked` in STIX terms and excluded from active queries. They remain in the database for historical correlation and audit purposes.

---

## Feed Health Monitoring

ThreatFlow tracks per-feed health metrics:

| Metric | Description |
|--------|-------------|
| `last_poll_at` | Timestamp of the most recent successful poll |
| `last_poll_count` | Number of new IOCs from the last poll |
| `error_count` | Consecutive poll failures |
| `accuracy_ratio` | True positive rate based on sighting feedback |
| `total_iocs` | Total IOCs contributed by this feed |

Feeds with `error_count > 5` are automatically paused and a VIGIL AMBER alert is raised.

---

## See Also

- [STIX 2.1 Integration](stix-integration.md) — feed ingestion produces STIX 2.1 objects
- [CITADEL Integration](citadel-integration.md) — MARSHAL gating for bulk ingestion, WORM event logging
- [Data Model](data-model.md) — `feeds` and `iocs` tables
- [API Reference](api-reference.md) — IOC ingestion endpoints
- [Configuration](configuration.md) — feed configuration variables
- [Troubleshooting](troubleshooting.md) — debugging feed poll failures
