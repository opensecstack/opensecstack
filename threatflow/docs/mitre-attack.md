# MITRE ATT&CK Mapping

ThreatFlow maps ingested IOCs to MITRE ATT&CK techniques (TTPs) to provide tactical context for defenders.

---

## How Mapping Works

### Automatic Mapping

ThreatFlow uses a rule-based classifier that examines IOC metadata and context to assign ATT&CK technique IDs:

| IOC Signal | Mapped Technique | Rationale |
|-----------|-----------------|-----------|
| IP/domain + port 443/80 in phishing context | T1566.001 (Spearphishing Attachment) | Web-delivered payload |
| IP/domain + C2 tag from feed | T1071.001 (Application Layer Protocol: Web) | HTTP(S) C2 channel |
| URL containing `/wp-admin/`, `/cgi-bin/` | T1190 (Exploit Public-Facing Application) | Web shell / exploit path |
| File hash + ransomware tag | T1486 (Data Encrypted for Impact) | Ransomware binary |
| Domain with DGA pattern | T1568.002 (Dynamic Resolution: DGA) | Domain generation algorithm |
| Email address in phishing feed | T1566 (Phishing) | Phishing sender |

### Feed-provided Mapping

Many feeds include ATT&CK technique IDs in their metadata. ThreatFlow preserves these when:
- The technique ID matches the ATT&CK format (`T[0-9]{4}(\.[0-9]{3})?`)
- The technique exists in the current ATT&CK version

### Manual Override

Analysts can manually tag IOCs with additional TTPs via the API:

```
PATCH /api/v1/iocs/{id}
{
  "ttp": ["T1071.001", "T1059.001"]
}
```

---

## ATT&CK Data Source

ThreatFlow ships with an embedded copy of the MITRE ATT&CK Enterprise matrix (STIX 2.1 format). This is updated with each ThreatFlow release.

| Matrix | Version | Object Count |
|--------|---------|-------------|
| Enterprise | v15 | 201 techniques, 424 sub-techniques |

---

## STIX Relationship Model

When ThreatFlow maps an IOC to a TTP, it creates a STIX Relationship object:

```json
{
  "type": "relationship",
  "id": "relationship--...",
  "relationship_type": "indicates",
  "source_ref": "indicator--<ioc-stix-id>",
  "target_ref": "attack-pattern--<technique-stix-id>",
  "confidence": 75,
  "created": "2026-03-31T10:00:00Z"
}
```

These relationships are included in exported STIX bundles, allowing downstream consumers (IRFlow, NIS2 Compass) to understand the tactical significance of each IOC.

---

## ATT&CK Heatmap

ThreatFlow generates an ATT&CK heatmap showing technique coverage across all active IOCs:

| Tactic | Top Techniques | IOC Count |
|--------|---------------|-----------|
| Initial Access | T1190, T1566, T1133 | — |
| Execution | T1059, T1203 | — |
| Command and Control | T1071, T1568, T1573 | — |
| Impact | T1486, T1490 | — |

This heatmap is available via:
- `GET /api/v1/attack/heatmap` (JSON, planned)
- React dashboard (planned)
- Grafana panel (planned)

---

## Integration with AUGUR

When CITADEL AUGUR publishes a security advisory with a CVE, ThreatFlow:

1. Queries its IOC store for indicators linked to that CVE
2. Creates STIX Vulnerability objects for the CVE
3. Links existing IOCs to the vulnerability via `indicates` relationships
4. Raises the confidence score of matching IOCs (confirmed by advisory)

This closes the loop between governance (AUGUR advisory) and intelligence (ThreatFlow IOC).

---

## See Also

- [STIX 2.1 Integration](stix-integration.md) — STIX Relationship objects used for ATT&CK links
- [IOC Feeds](ioc-feeds.md) — how feed metadata informs automatic TTP mapping
- [Data Model](data-model.md) — `ttp_tags` table
- [API Reference](api-reference.md) — PATCH /iocs/{id} for manual TTP assignments
- [CITADEL Integration](citadel-integration.md) — AUGUR advisory cross-reference
