# MITRE ATT&CK Coverage

SecureLab maps its built-in attack kinds to MITRE ATT&CK techniques
and exposes a coverage snapshot via `GET /api/v1/coverage`.

## Attack kind → ATT&CK technique mapping

The mapping is a static table (`internal/reporting/mitre.go`,
`MITREMapping`), covering all 15 built-in attack kinds:

| Attack kind | Technique ID | Name | Tactic |
|---|---|---|---|
| `bola` | T1078 | Valid Accounts | Initial Access, Defense Evasion, Persistence, Privilege Escalation |
| `authbypass` | T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion, Lateral Movement |
| `massassignment` | T1548 | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |
| `ratelimitbypass` | T1499 | Endpoint Denial of Service | Impact |
| `ssrf` | T1090 | Proxy | Command and Control |
| `misconfiguration` | T1592 | Gather Victim Host Information | Reconnaissance |
| `synflood` | T1498.001 | Network Denial of Service: Direct Network Flood | Impact |
| `udpflood` | T1498.001 | Network Denial of Service: Direct Network Flood | Impact |
| `httpflood` | T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood | Impact |
| `slowloris` | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood | Impact |
| `portscan` | T1046 | Network Service Discovery | Discovery |
| `endpointenum` | T1595.003 | Active Scanning: Wordlist Scanning | Reconnaissance |
| `versiondetect` | T1082 | System Information Discovery | Discovery |
| `dataexfil` | T1530 | Data from Cloud Storage | Collection |
| `dnstunnel` | T1071.004 | Application Layer Protocol: DNS | Command and Control |

`reporting.LookupByKind(kind)` resolves this mapping at runtime for
report generation.

## Coverage table and endpoint

Coverage is stored in the `mitre_coverage` table (see
`internal/db/migrations/004_coverage.sql`):

| Column | Type | Notes |
|---|---|---|
| `technique_id` | text, primary key | e.g. `T1059.001` |
| `technique_name` | text | |
| `tactic` | text | |
| `scenario_count` | int | |
| `last_detected_at` | timestamptz, nullable | |
| `detection_rate` | numeric(5,2) | |

`GET /api/v1/coverage` (analyst role or higher) returns every row via
`db.ListCoverage`, ordered by `technique_id`:

```json
{
  "entries": [
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "tactic": "Initial Access, Defense Evasion, Persistence, Privilege Escalation",
      "scenario_count": 3,
      "last_detected_at": "2026-01-15T09:06:00Z",
      "detection_rate": 87.5
    }
  ]
}
```

`db.UpsertCoverage` exists to insert/update a row on conflict, but is
not currently called from any run-completion or scheduling code path
— nothing in `internal/scenarios` or `internal/detection` writes to
`mitre_coverage` automatically today. Populating and keeping this
table current is an operational/administrative task until that wiring
lands.

## Future / Not Yet Implemented

The following are reasonable, commonly-requested extensions to this
feature that do **not** exist in the codebase today — no per-tactic
rollup percentages, no `no_scenario` / `scenario_exists` / `executed`
/ `validated` coverage state machine, no ATT&CK Navigator layer export
endpoint, and no automatic coverage-decay detection between runs. Any
of these would need to be designed and built, not assumed to be
present.

## Related

- [docs/api.md](api.md) — `/api/v1/coverage` endpoint reference
- [docs/scenario-spec.md](scenario-spec.md) — scenario YAML format
- [docs/citadel-integration.md](citadel-integration.md) — CITADEL evidence emission
