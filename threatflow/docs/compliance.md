# ThreatFlow NIS2 Compliance Mapping

## Overview

ThreatFlow contributes to NIS2 Directive (2022/2555) compliance under Article 21(2).
As the threat intelligence hub in the opensecstack ecosystem, ThreatFlow provides
automated evidence generation, IOC-driven incident enrichment, and structured STIX 2.1
exports that feed directly into NIS2Compass assessments. Every operation is
WORM-logged via CITADEL, producing a tamper-proof audit trail that satisfies
NIS2 record-keeping requirements.

---

## Article 21(2) Measure Mapping

### (b) Incident Handling

- ThreatFlow enriches IRFlow incidents with IOC context
- IOC correlation provides attack attribution evidence
- STIX 2.1 bundles serve as structured incident artifacts
- WORM audit trail provides tamper-proof evidence chain
- Sighting records (see `sightings` table in [data-model.md](data-model.md)) link IOCs
  to specific IRFlow incidents, providing a machine-readable evidence trail
- MITRE ATT&CK mappings on correlated IOCs give incident responders immediate
  tactical context (see [mitre-attack.md](mitre-attack.md))

### (d) Supply Chain Security

- Monitors supply chain IOCs from multiple threat feeds
- Alerts on IOCs matching organisational infrastructure
- STIX exports serve as evidence artifacts for NIS2Compass assessments
- Automatic MITRE ATT&CK mapping identifies supply chain TTPs (T1195.*)
- Feed confidence scoring ensures only high-quality intelligence informs
  supply chain risk decisions
- Cross-feed correlation detects coordinated supply chain campaigns that
  span multiple indicator types

### (e) Security in Network and Information Systems

- Continuous IOC monitoring identifies threats to network infrastructure
- Integration with APIGuard validates API security posture against known threats
- Feed-based alerting for newly discovered vulnerabilities
- IOC types (`ipv4-addr`, `domain-name`, `url`) directly map to network-layer
  indicators, enabling firewall and proxy rule generation
- STIX Vulnerability objects link CVEs to observed indicators, tying
  vulnerability management to active threat intelligence

### (h) Policies and Procedures for Cryptography

- Tracks cryptographic vulnerability IOCs (weak algorithms, compromised keys)
- STIX Vulnerability objects reference relevant CVEs
- Alerts when organisational cryptographic infrastructure matches IOC patterns
- IOC tags such as `weak-crypto`, `compromised-certificate` filter
  crypto-relevant indicators for targeted reporting
- Supports certificate-hash IOC type for monitoring revoked or compromised
  TLS certificates

---

## Evidence Generation for NIS2Compass

### Automated Evidence Pipeline

1. ThreatFlow ingests IOCs from configured feeds
2. Correlation engine matches IOCs to organisational assets
3. STIX bundle generated with relevant indicators + relationships
4. Bundle exported to NIS2Compass as assessment artifact
5. NIS2Compass links the artifact to the appropriate Article 21(2) control
6. Auditors can trace from control back through bundle to original IOC source

### Supported Evidence Types

| NIS2 Control | Evidence Type               | ThreatFlow Source          |
|--------------|-----------------------------|----------------------------|
| art21_b      | Incident IOC report         | Correlation matches        |
| art21_d      | Supply chain threat assessment | Feed analysis           |
| art21_e      | Network threat landscape    | IOC summary by type        |
| art21_h      | Crypto vulnerability scan   | CVE-based IOC filter       |

### Report Formats

ThreatFlow NIS2 reports are available in two formats:

- **JSON** (default) -- STIX 2.1 bundle containing indicators, relationships,
  and sightings relevant to the requested control
- **PDF** -- Human-readable summary with IOC tables, ATT&CK heatmap, and
  feed confidence breakdown (planned, v0.5.0)

### Example: Generate NIS2 Evidence

```bash
# Export IOC evidence for supply chain control
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8091/api/v1/reports/nis2?control=art21_d&period=Q1-2026" \
  -o supply_chain_evidence.json

# Upload to NIS2Compass
curl -X POST "http://nis2compass:5000/api/v1/assessments/$ASSESSMENT_ID/artifacts" \
  -H "Authorization: Bearer $NIS2_TOKEN" \
  -F "file=@supply_chain_evidence.json" \
  -F "artifact_type=evidence" \
  -F "control_id=art21_d" \
  -F "description=ThreatFlow supply chain IOC evidence Q1 2026"
```

### Example: Query Crypto-relevant IOCs

```bash
# List IOCs tagged with cryptographic relevance
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8091/api/v1/iocs?tags=weak-crypto,compromised-certificate&confidence_min=60"
```

### Report Scheduling

For recurring NIS2 evidence generation, configure a cron-based export:

| Variable                             | Example           | Description                    |
|--------------------------------------|-------------------|--------------------------------|
| `THREATFLOW_NIS2_REPORT_CRON`       | `0 6 1 * *`       | Monthly on the 1st at 06:00    |
| `THREATFLOW_NIS2_REPORT_CONTROLS`   | `art21_b,art21_d` | Controls to include            |
| `THREATFLOW_NIS2_REPORT_DEST`       | `nis2compass`     | Target: `nis2compass` or `s3`  |

---

## CITADEL WORM Audit Trail

- Every ThreatFlow operation is logged to CITADEL WORM
- Chain-hashed entries provide tamper-evidence
- 7-year retention per RFC-0003
- Events: `ioc.ingested`, `feed.polled`, `bundle.exported`, `correlation.match`

### WORM Event Schema

Each WORM event emitted by ThreatFlow follows this structure:

```json
{
  "event_type": "ioc.ingested",
  "timestamp": "2026-03-31T12:00:00Z",
  "actor": "feed:alienvault-otx",
  "resource": "ioc:550e8400-e29b-41d4-a716-446655440000",
  "detail": {
    "ioc_type": "ipv4-addr",
    "ioc_value": "198.51.100.42",
    "feed_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
    "confidence": 72
  },
  "chain_hash": "sha256:ab12cd34..."
}
```

### Event Types

| Event                | Trigger                                      | Detail Fields                        |
|----------------------|----------------------------------------------|--------------------------------------|
| `ioc.ingested`      | New IOC persisted                            | ioc_type, value, feed_id, confidence |
| `ioc.deduplicated`  | Duplicate IOC merged                         | existing_id, new_feed, delta         |
| `feed.polled`       | Feed poll completed                          | feed_id, ioc_count, duration_ms      |
| `feed.error`        | Feed poll failed                             | feed_id, error, consecutive_failures |
| `bundle.exported`   | STIX bundle generated for downstream         | bundle_id, object_count, consumer    |
| `bundle.imported`   | STIX bundle ingested from external source    | bundle_id, object_count, source      |
| `correlation.match` | IOC matched to ecosystem resource            | ioc_id, platform, resource_id        |
| `report.generated`  | NIS2 evidence report created                 | control, period, artifact_count      |

---

## NIS2 Article 23 -- Incident Notification

### Notification Trigger

When ThreatFlow correlates IOCs with an active P1/P2 incident in IRFlow, it
evaluates whether the incident crosses NIS2 significance thresholds. If it does,
ThreatFlow sets the `nis2_notify_required` flag on the IRFlow incident via the
integration API.

### Notification Timeline

| Severity | Threshold                                       | Deadline  |
|----------|-------------------------------------------------|-----------|
| P1       | Any correlation with known APT or critical CVE  | 24 hours  |
| P2       | 3+ distinct IOC matches from 2+ feeds           | 72 hours  |

### Evidence Chain

The full evidence chain for an NIS2 notification is:

1. **ThreatFlow IOC** -- original indicator with feed provenance and confidence
2. **Correlation sighting** -- link between IOC and IRFlow incident
3. **IRFlow incident** -- incident timeline, impact assessment, containment actions
4. **NIS2Compass notification** -- formal notification record with competent authority

### Integration Flow

```
ThreatFlow                IRFlow                  NIS2Compass
    |                        |                        |
    |-- correlation.match -->|                        |
    |-- set nis2_notify ---->|                        |
    |                        |-- create notification ->|
    |                        |                        |-- submit to CSIRT
    |                        |                        |
```

### Configuration

| Variable                                | Default | Description                          |
|-----------------------------------------|---------|--------------------------------------|
| `THREATFLOW_NIS2_NOTIFY_ENABLED`       | `false` | Enable NIS2 notification flagging    |
| `THREATFLOW_NIS2_P1_THRESHOLD`         | `1`     | Min IOC matches for P1 notification  |
| `THREATFLOW_NIS2_P2_THRESHOLD`         | `3`     | Min IOC matches for P2 notification  |
| `THREATFLOW_NIS2_P2_MIN_FEEDS`        | `2`     | Min distinct feeds for P2            |

---

## Compliance Validation

To verify that ThreatFlow is correctly generating NIS2 evidence, run the
built-in compliance check:

```bash
# Validate evidence generation pipeline
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8091/api/v1/reports/nis2/validate"
```

This endpoint checks:

- At least one active feed is configured and polling
- WORM logging is connected and chain integrity is valid
- NIS2Compass integration is reachable (if configured)
- Evidence can be generated for each mapped control

---

## Further Reading

- [CITADEL Integration](citadel-integration.md) -- MARSHAL governance and WORM logging details
- [STIX 2.1 Integration](stix-integration.md) -- bundle format and TAXII polling
- [MITRE ATT&CK Mapping](mitre-attack.md) -- TTP classification
- [Data Model](data-model.md) -- database schema for IOCs, sightings, and bundles
- NIS2 Directive full text: [EUR-Lex 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555)
