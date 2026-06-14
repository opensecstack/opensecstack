# NIS2 Compliance Mapping

## Scope

This document maps OpenScrub capabilities to the requirements of Directive (EU) 2022/2555 (NIS2), specifically Article 21 — security measures for essential and important entities. It is intended for operators preparing technical evidence packages for competent authorities and internal audits.

OpenScrub does not constitute a complete NIS2 compliance programme. It addresses the network availability and resilience dimension.

---

## NIS2 Article 21 — Relevant Technical Measures

NIS2 Article 21(2) requires entities to take appropriate technical measures including:

| Article 21(2) sub-clause | Requirement | OpenScrub coverage |
|--------------------------|-------------|-------------------|
| (a) Risk analysis and security policies | DDoS risk assessment | Partial — event data supports risk quantification |
| (b) Incident handling | Detection and response to network attacks | Direct — detection engine + mitigation pipeline |
| (c) Business continuity and availability | Maintaining availability under attack | Direct — XDP drop and BGP blackhole preserve upstream capacity |
| (e) Security in network and systems | Network-layer security controls | Direct — XDP filtering at kernel boundary |
| (f) Policies on cryptography | Not applicable | Out of scope |
| (h) Multi-factor authentication | Not applicable to DDoS | Out of scope |

---

## DDoS Protection as a NIS2 Availability Measure

NIS2 requires essential entities to maintain the availability of services that society depends on. Volumetric DDoS attacks are one of the primary availability threats.

OpenScrub provides:

- **Detection** with configurable response times (default: 5-second evaluation cycle).
- **Automated mitigation** within seconds of threshold breach without operator intervention.
- **Proportional response** via the three-tier model — mitigation is scaled to attack severity, avoiding unnecessary traffic disruption.
- **Protected prefix scoping** — mitigation is bounded to declared protected ranges, preventing inadvertent impact on unrelated address space.

---

## Incident Reporting via CITADEL ARBITER

NIS2 Article 23 requires entities to notify competent authorities of significant incidents within 24 hours (early warning) and 72 hours (notification).

OpenScrub emits structured events to CITADEL ARBITER for every attack event that reaches severity High or Critical. CITADEL ARBITER is responsible for aggregating events and generating the notifications required by Article 23.

Event fields emitted to CITADEL ARBITER:

| Field | Description |
|-------|-------------|
| `event_id` | Unique event identifier |
| `affected_prefix` | Victim IP prefix |
| `attack_type` | Protocol and attack class |
| `severity` | Low / Medium / High / Critical |
| `start_time` | UTC timestamp of detection |
| `end_time` | UTC timestamp of clearance (or null if ongoing) |
| `peak_pps` | Maximum observed PPS |
| `peak_bps` | Maximum observed BPS |
| `mitigation_tier` | Tier applied (1, 2, or 3) |
| `source` | `openscrub` |

Configure the CITADEL ARBITER endpoint under `integrations.citadel_arbiter` in `openscrub.yaml`.

---

## Log Retention for NIS2 Audit Trails

NIS2 does not specify a minimum log retention period, but audit practice and sector-specific guidance typically require at least 12 months of security event logs.

OpenScrub writes the following to the database (configured in `openscrub.yaml` under `database`):

- All detection events with full field set.
- All mitigation state transitions with operator identity where applicable.
- All rollback and manual override actions.
- All IOC feed ingestion events.

Set the retention policy on your database to match your competent authority's expectations. There is no built-in log deletion — retention management is the operator's responsibility.

For long-term archival, export events periodically:

```bash
openscrub export events --from 2026-01-01 --to 2026-04-01 --format json > events-q1-2026.json
```

---

## Generating NIS2 Compliance Evidence

To produce an evidence report for a specific time period:

```bash
openscrub report nis2 --from 2026-01-01 --to 2026-03-31 --output nis2-q1-2026.json
```

The report includes:

- Total attack events detected and mitigated.
- Mean time to detect (MTTD) and mean time to mitigate (MTTM).
- Tier distribution of mitigations applied.
- All events emitted to CITADEL ARBITER within the period.
- Uptime of protected prefixes during attack events (derived from mitigation clearance timestamps).

The JSON output can be submitted directly to CITADEL ARBITER or imported into a GRC platform. Human-readable HTML output is available with `--format html`.
