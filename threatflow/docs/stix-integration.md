# STIX 2.1 Integration

ThreatFlow uses STIX 2.1 (Structured Threat Information Expression) as its native intelligence format. All IOCs are normalised to STIX objects internally, and all exports use STIX 2.1 bundles.

---

## Supported STIX Object Types

### STIX Domain Objects (SDOs)

| Type | Usage in ThreatFlow |
|------|-------------------|
| `indicator` | Primary IOC representation — every ingested IOC becomes an Indicator |
| `attack-pattern` | MITRE ATT&CK techniques linked to indicators |
| `malware` | Malware families associated with IOC campaigns |
| `threat-actor` | Attribution when available from feed metadata |
| `campaign` | Groups related indicators under a named operation |
| `vulnerability` | CVEs linked to IOCs via AUGUR advisory cross-reference |
| `identity` | Feed source identity objects |

### STIX Relationship Objects (SROs)

| Type | Usage |
|------|-------|
| `relationship` | Links indicators to attack-patterns, malware, campaigns |
| `sighting` | Records when an IOC is observed in APIGuard scans or IRFlow incidents |

### STIX Cyber-observable Objects (SCOs)

| Type | Pattern Example |
|------|----------------|
| `ipv4-addr` | `[ipv4-addr:value = '198.51.100.42']` |
| `ipv6-addr` | `[ipv6-addr:value = '2001:db8::1']` |
| `domain-name` | `[domain-name:value = 'evil.example.com']` |
| `url` | `[url:value = 'https://evil.example.com/payload']` |
| `file` | `[file:hashes.SHA-256 = 'abc123...']` |
| `email-addr` | `[email-addr:value = 'phisher@example.com']` |

---

## TAXII 2.1 Feed Polling

ThreatFlow implements a TAXII 2.1 client that polls configured servers at regular intervals.

### Configuration

```yaml
# threatflow.yaml (or environment variables)
feeds:
  - name: "alienvault-otx"
    type: taxii21
    url: "https://otx.alienvault.com/taxii/"
    collection: "default"
    poll_interval: 15m
    api_key: "${THREATFLOW_FEED_OTX_KEY}"
    confidence_base: 70

  - name: "abuse-ch-urlhaus"
    type: csv
    url: "https://urlhaus.abuse.ch/downloads/csv/"
    poll_interval: 1h
    confidence_base: 80

  - name: "internal-misp"
    type: misp
    url: "https://misp.internal/events/restSearch"
    api_key: "${THREATFLOW_FEED_MISP_KEY}"
    poll_interval: 10m
    confidence_base: 90
```

### Poll Lifecycle

1. **Discovery** — query TAXII API root and collection metadata
2. **Poll** — request objects added/modified since last poll timestamp
3. **Parse** — extract STIX objects from the TAXII envelope
4. **Deduplicate** — check SHA-256 of each indicator pattern against existing store
5. **Score** — assign confidence = `confidence_base * feed_accuracy_ratio`
6. **Persist** — store to PostgreSQL with full STIX metadata
7. **WORM log** — emit `threatflow.feed.polled` event to CITADEL

### Supported Feed Types

| Type | Format | Protocol |
|------|--------|----------|
| `taxii21` | STIX 2.1 bundles | HTTPS + TAXII 2.1 API |
| `csv` | Column-delimited (IP, domain, URL, hash) | HTTPS GET |
| `misp` | MISP JSON events | HTTPS + MISP REST API |
| `manual` | JSON via POST /api/v1/iocs | HTTP API |

---

## Bundle Export

ThreatFlow can export filtered STIX 2.1 bundles for downstream consumers:

```
GET /api/v1/stix/bundles/export?since=2026-03-01&type=indicator&confidence_min=70
Accept: application/stix+json;version=2.1
```

The response is a valid STIX 2.1 bundle containing all matching objects and their relationships.

---

## STIX ID Generation

ThreatFlow generates deterministic STIX IDs to support deduplication:

```
indicator--SHA256(pattern_type + ":" + pattern_value)[:36 as UUID v5]
```

This ensures the same indicator from different feeds produces the same STIX ID, enabling automatic deduplication and relationship merging.
