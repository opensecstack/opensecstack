# IRFlow — NIS2 Mapping

IRFlow is the incident response workbench of the OpenSecStack
ecosystem. It is explicitly designed to satisfy the operational
requirements of NIS2 (Directive 2022/2555) for essential and important
entities. This document maps IRFlow features onto the directive's
articles so auditors can trace evidence back to obligations and
operators know which controls depend on which features.

For the Article 21(2) reference in full, see [../../nis2compass/docs/nis2-controls-reference.md](../../nis2compass/docs/nis2-controls-reference.md).

## Article 21(2) — risk management measures

| Measure | Title | IRFlow contribution |
|---|---|---|
| (a) | Risk analysis & security policies | Incident severity taxonomy + playbooks encode the organisation's response policy in runnable form |
| (b) | **Incident handling** | **IRFlow's core domain** — lifecycle, timeline, evidence chain |
| (c) | Business continuity | Containment + recovery action types; incident state machine guards premature closure |
| (d) | Supply chain security | Webhooks from APIGuard + ThreatFlow surface upstream-supplied findings |
| (e) | Network & information system security | Action log records every containment decision with WORM proof |
| (f) | Effectiveness assessment | Metrics export (`irflow_incidents_resolved_total{severity}`) feeds quarterly review |
| (g) | Cyber hygiene & training | Out of scope — see CyberPath (planned) |
| (h) | Cryptography | HS256 JWT, HMAC-SHA256 webhooks, Argon2id + pepper password hashing |
| (i) | HR security & access control | RBAC with SoD enforcement ([rbac-guide.md](./rbac-guide.md)) |
| (j) | MFA & secured communications | TLS terminated at ingress; MFA delegated to the upstream IdP |

Measure **(b)** — Incident Handling — is where IRFlow carries the
weight of the mapping. The other rows reflect collateral support; do
not claim IRFlow as the primary evidence for (a) or (g).

## Article 23 — incident notification

NIS2 Article 23 requires essential entities to notify the national
CSIRT or competent authority of significant incidents:

| Phase | Deadline | IRFlow feature |
|---|---|---|
| Early warning | 24 hours after becoming aware | Automatic on incident creation with severity P1/P2 — pushed to NIS2 Compass Article 23 endpoint |
| Full notification | 72 hours | Manual today; v1.1 adds an "upgrade-notification" CLI that re-submits with the current timeline |
| Final report | 1 month | Out of scope for IRFlow — use NIS2 Compass export |

IRFlow's contribution to the 24-hour path is:

```
POST /api/v1/incidents  (severity P1)
    ↓
incident.Service.Create
    ├─► persist incident
    ├─► WORM anchor
    └─► async goroutine → NIS2Client.NotifyIncident
            └─► POST https://nis2compass/api/v1/notifications
                    (includes incident_id, severity, category, timeline)
```

The notification is async on a detached goroutine so a slow Compass
API never blocks creation — it would otherwise push IRFlow past the
24-hour deadline itself.

Successful notification records `nis2_notified_at` on the incident
row. Failure is logged and surfaces via
`irflow_governance_calls_total{target="nis2",result="failure"}`;
operators retrigger manually until v1.1's retry worker lands.

## Configuration

```bash
IRFLOW_NIS2_API_URL=https://nis2compass.internal
IRFLOW_NIS2_API_KEY=<from secret manager>
IRFLOW_NIS2_ASSESSMENT_ID=assess_2026Q2
IRFLOW_NIS2_MEASURE_REF=b            # Art. 21(2)(b) Incident Handling
```

Empty `API_KEY` disables the integration — IRFlow runs without
Article 23 notifications. For NIS2-in-scope entities that is a
compliance hole; document the mitigation in your NIS2 Compass
assessment.

## Evidence chain for auditors

An auditor tracing a single incident sees:

1. **Incident row** in IRFlow with the business facts (title, severity,
   timeline).
2. **WORM entries** in CITADEL keyed by `worm_entry_id` — one per
   action, plus the `incident.created` anchor.
3. **Chain anchor signatures** proving the WORM entries predate the
   audit (cannot have been backfilled).
4. **Article 23 notification record** in NIS2 Compass with a timestamp
   that must lie within 24 hours of `incident.created`.
5. **NIS2 Compass assessment** showing Article 21(2)(b) compliance
   evidence referencing these records.

Each step is independently verifiable — even if IRFlow's database were
corrupted, a full reconstruction is possible from CITADEL + NIS2
Compass alone.

## When IRFlow is *not* enough

NIS2 compliance also requires:

- A governance policy document — draft and store outside IRFlow (NIS2
  Compass supports artifact uploads).
- Staff training records — Article 21(2)(g); OpenSecStack plans
  CyberPath for this but today you need an external LMS.
- Third-party risk assessment — supply chain; typically outside the
  platform's scope.

IRFlow's NIS2 mapping covers the **operational** half of the
obligation; the documentation half sits with NIS2 Compass + your
own written policies.

## Related

- [Governance integration](./governance-integration.md) — CITADEL side
- [API reference § Incidents](./api.md#incidents) — notification fields in the JSON
- [../../nis2compass/docs/nis2-controls-reference.md](../../nis2compass/docs/nis2-controls-reference.md) — full Article 21(2) reference
- [../../docs/security-maturity.md](../../docs/security-maturity.md) — tier reference for "NIS2-ready"
