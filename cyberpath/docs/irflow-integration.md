# CyberPath ↔ IRFlow Integration

> Interface contract for incident-driven retraining. IRFlow is the
> caller for the inbound trigger; CyberPath calls IRFlow back when a
> mandated retraining completes. Lands with v1.0.0.
>
> The HMAC scheme below matches the ecosystem-wide pattern documented
> in [../../irflow/docs/webhook-spec.md](../../irflow/docs/webhook-spec.md)
> and [../../vertguard/docs/threatflow-integration.md](../../vertguard/docs/threatflow-integration.md):
> Stripe-style `timestamp + "." + raw_body`, HMAC-SHA256, ±5 min
> tolerance, 90-day secret rotation.

## Why this integration

After an incident, the team that was involved should retrain on the
specific skill gap the incident exposed. Today this is a manual
loop: a CSIRT lead writes a postmortem, a CISO reads it, an HR
admin assigns LMS modules a week later, and by then the lesson is
stale.

IRFlow already has the data needed to short-circuit that loop. It
knows:

- the incident type (phishing, privilege escalation, etc.)
- the affected users (from playbook outputs and timeline entries)
- the severity (P1–P4)

CyberPath knows which tracks address which skill gaps. The
integration is a thin signal: IRFlow tells CyberPath an incident
happened and proposes tracks; CyberPath optionally auto-enrols the
affected users and notifies an instructor. When the retraining
completes, CyberPath tells IRFlow so the incident can be closed
out.

The benefit is not automation for its own sake — it is reducing
the time-to-retraining from weeks to hours, which is when the
lesson is still vivid for the affected people.

## Trigger model

IRFlow's outbound webhook calls CyberPath's inbound endpoint:

```
POST https://cyberpath.internal:8086/api/v1/cyberpath/incident_trigger
```

CyberPath validates the HMAC signature, looks up the
incident-type → track-set mapping, and either:

- **auto-enrols** the affected users in a new cohort, or
- **notifies an instructor** (admin user with `instructor` role) who
  reviews and approves the enrolment manually

The choice between auto-enrol and notify is a deployment-level
config (`CYBERPATH_IRFLOW_AUTOENROL=true|false`, default `false`).
For organisations new to the platform, manual approval is the safer
default; mature deployments flip it on once they trust the mapping.

## API contract — inbound (IRFlow → CyberPath)

### Request

```
POST /api/v1/cyberpath/incident_trigger
Content-Type: application/json
X-IRFlow-Signature: sha256=<hex>
X-IRFlow-Timestamp: <unix-seconds>
X-IRFlow-Event-Id: <uuid>
```

```json
{
  "event_id":   "irflow-evt-2027-08-14-00193",
  "event_type": "irflow.incident.retraining_required",
  "incident_id": "inc_2027_08_14_004",
  "incident": {
    "type":      "phishing",
    "severity":  "P2",
    "title":     "Targeted phish against finance team",
    "opened_at": "2027-08-14T09:11:02Z",
    "closed_at": "2027-08-14T16:42:18Z"
  },
  "affected_users": [
    "user_a1b2c3",
    "user_d4e5f6",
    "user_g7h8i9"
  ],
  "suggested_tracks": [
    "phishing-recognition"
  ],
  "occurred_at": "2027-08-14T16:45:00Z"
}
```

Notes on fields:

- `incident.type` is IRFlow's incident-type taxonomy (see the
  lookup table below for supported values).
- `affected_users` is a list of CyberPath user ids. IRFlow is
  responsible for the IRFlow-incident-actor → CyberPath-user-id
  resolution; CyberPath does not look up users by email or other
  PII here.
- `suggested_tracks` is optional. If absent, CyberPath uses its
  built-in mapping. If present, it overrides for this trigger
  only — useful when an IR lead wants to nominate a specific
  track post-mortem.

### Response (202 Accepted)

```json
{
  "trigger_id":              "cpt_2027_08_14_00031",
  "incident_id":             "inc_2027_08_14_004",
  "cohort_id":               "cohort_2027_08_phishing_inc04",
  "enrolled_user_count":     3,
  "skipped_user_count":      0,
  "skipped_reasons":         {},
  "tracks_assigned": [
    "phishing-recognition"
  ],
  "recommended_completion_by": "2027-08-28T23:59:59Z",
  "mode":                    "auto_enrol"
}
```

`mode` is one of `auto_enrol` (cohort created and users enrolled) or
`pending_review` (instructor notified, no enrolment yet).

`skipped_reasons` is a map of `user_id → reason` for users IRFlow
flagged but CyberPath did not enrol. Common reasons: `already_enrolled`,
`opted_out`, `unknown_user`, `cert_still_valid`.

### Response codes

| Code | Meaning |
|---|---|
| `202` | Trigger accepted; processing complete or queued |
| `400` | Malformed body or unknown `incident.type` |
| `401` | Missing/invalid HMAC signature, or timestamp outside ±5 min |
| `409` | Duplicate `event_id` (replay) — idempotent return of original response |
| `503` | `CYBERPATH_IRFLOW_KEY_SECRET` not configured — endpoint disabled |

### HMAC signing

The signing scheme is identical to IRFlow's own webhook receivers
and the wider ecosystem pattern. The signed input is:

```
signed_payload = timestamp + "." + raw_body
signature      = hex(HMAC-SHA256(CYBERPATH_IRFLOW_KEY_SECRET, signed_payload))
```

`raw_body` is the exact bytes on the wire — no re-serialisation.
Verification rejects on:

- signature mismatch
- timestamp outside ±5 min skew (`CYBERPATH_IRFLOW_CLOCK_SKEW`,
  default `5m`)
- replayed `X-IRFlow-Event-Id` (CyberPath persists the last 24 h of
  event ids in a small dedup table)

Secret rotation: 90 days. Both sides accept old + new secret during
a 24 h overlap window. Rotation procedure documented in the
operator handbook.

## API contract — outbound (CyberPath → IRFlow)

When a learner enrolled by an incident-trigger completes the
mandated track, CyberPath posts to IRFlow:

```
POST https://irflow.internal:8085/api/v1/webhooks/cyberpath
Content-Type: application/json
X-Irflow-Signature: sha256=<hex>
X-Irflow-Timestamp: <unix-seconds>
X-Irflow-Event-Id: <uuid>
```

```json
{
  "event_id":   "cyberpath-evt-2027-08-22-00088",
  "event_type": "cyberpath.incident_remediation_completed",
  "incident_id": "inc_2027_08_14_004",
  "trigger_id":  "cpt_2027_08_14_00031",
  "user_id":     "user_a1b2c3",
  "track_id":    "phishing-recognition",
  "track_version": "1.4.0",
  "completion_id": "<uuid>",
  "completed_at":  "2027-08-22T11:09:42Z",
  "evidence_hash": "blake3:<hex>",
  "citadel_ledger_id": "<ledger id>",
  "occurred_at":   "2027-08-22T11:09:42Z"
}
```

IRFlow's behaviour on receipt: append a timeline entry to the
referenced incident, and if the incident's `pending_actions`
include a remediation-training item matching this `trigger_id`,
mark it complete. If all `pending_actions` are now done, IRFlow
proposes the incident for closure (it does not auto-close —
human-in-the-loop for that final step).

CyberPath emits one of these events per (user × track), not one
per cohort. A 3-user cohort completing the same track produces
three outbound webhooks.

## Reverse direction summary

```
   IRFlow                          CyberPath
     │                               │
     │  POST incident_trigger        │
     │  (HMAC, w/ affected_users)    │
     ├──────────────────────────────►│
     │                               │
     │  202 Accepted                 │
     │  (cohort_id, mode)            │
     │◄──────────────────────────────┤
     │                               │
     │           ... time passes;
     │           learners complete the track ...
     │                               │
     │  POST /webhooks/cyberpath     │
     │  cyberpath.incident_          │
     │  remediation_completed        │
     │◄──────────────────────────────┤
     │                               │
     │  200 OK                       │
     ├──────────────────────────────►│
     │                               │
     │  (IRFlow updates incident,
     │   may propose closure)
```

## Incident-type → track-set lookup

Default mapping shipped in v1.0.0. Each deployment can override via
`CYBERPATH_IRFLOW_TRACK_MAPPING` (a YAML file path).

| IRFlow `incident.type` | Recommended tracks (slugs) | Rationale |
|---|---|---|
| `phishing` | `phishing-recognition`, `nis2-art21-awareness` | direct skill gap; awareness reinforces hygiene |
| `business_email_compromise` | `phishing-recognition` | BEC is phishing's most damaging variant |
| `credential_compromise` | `phishing-recognition`, `nis2-art21-awareness` | most credential losses originate in phishing |
| `privilege_escalation` | `linux-hardening`, `secure-coding` | hardening + dev-side mitigation |
| `web_app_compromise` | `secure-coding`, `api-security` | OWASP Top 10 + API Top 10 coverage |
| `api_abuse` | `api-security` | direct match |
| `malware_outbreak` | `network-forensics`, `incident-response-basics` | post-incident analytical skills |
| `supply_chain` | `secure-coding` (sec.5 supply-chain section) | the dev-side controls live here |
| `policy_violation` | `nis2-art21-awareness` | baseline awareness |
| `insider_threat` | `nis2-art21-awareness` | hygiene + access-control awareness; technical retraining alone misses the point |
| `data_exfiltration` | `network-forensics`, `incident-response-basics` | detection + response skills |
| `ransomware` | `incident-response-basics`, `network-forensics`, `linux-hardening` | full triple — IR, forensics, hardening |
| `ddos` | — | operational issue, not a training gap; trigger ignored with `mode: skipped` |
| `physical_security` | — | out of scope for CyberPath |
| `unknown` | `nis2-art21-awareness` | fallback baseline |

Track slugs reference [module-list.md](./module-list.md). New track
additions update this table; mappings are not invented here for
tracks that don't yet exist.

The `recommended_completion_by` field returned in the trigger
response is computed as `now + CYBERPATH_IRFLOW_RETRAINING_SLA`,
default `14 days`. Severity-aware overrides are possible (P1
incidents → 7 days) but are deployment policy.

## Scoping rules

To keep this integration from becoming a broadcast tool, several
rules are enforced regardless of trigger content:

- **Only enrol IRFlow's `affected_users` list.** CyberPath does
  not expand the scope to "everyone in the same team" or "everyone
  on the same project". The bounded user set is the trigger
  contract.
- **Explicit opt-out.** Users can set
  `notification_preferences.incident_retraining = false` on their
  CyberPath profile. Opted-out users appear in `skipped_users`
  with reason `opted_out` and the trigger response surfaces this
  to IRFlow.
- **No org-wide rollout from a trigger.** If `affected_users` is
  empty or larger than `CYBERPATH_IRFLOW_MAX_TRIGGER_USERS` (default
  100), the trigger is queued for admin sign-off (`mode: pending_review`)
  rather than auto-processed.
- **Cert-still-valid skip.** If a user already holds a non-expired
  certification on the recommended track, CyberPath skips them
  with reason `cert_still_valid`. The CSIRT lead sees this in
  IRFlow and can decide to manually re-trigger if they disagree.

## Failure modes

| Condition | CyberPath behaviour | IRFlow behaviour |
|---|---|---|
| CyberPath unreachable (5xx / timeout) | n/a | retry with exponential backoff: 1s, 2s, 4s, 8s, 16s (5 attempts), then DLQ |
| HMAC mismatch | return 401 | log + DLQ (do not retry blindly — secret rotation issue) |
| Replayed `event_id` | return 202 with the original response (idempotent) | n/a |
| Unknown `incident.type` | return 400 | DLQ + alert |
| IRFlow unreachable on outbound | n/a | CyberPath retries with the same 5-attempt schedule, then queues locally |
| Extended IRFlow outage | continue serving learners and emitting CITADEL events; queue outbound `cyberpath.incident_remediation_completed` events for replay | n/a |
| CITADEL down at trigger time | enrolment proceeds; the audit event (`cyberpath.incident_triggered_enrollment`) goes through the same WAL pattern as the rest of the CITADEL emit path | n/a |

The outbound retry schedule and DLQ behaviour mirror VertGuard's
ThreatFlow client (see [../../vertguard/docs/threatflow-integration.md](../../vertguard/docs/threatflow-integration.md)).
DLQ entries are surfaced in `/metrics` as
`cyberpath_irflow_dlq_depth`; alert at sustained > 10.

## Audit

Every auto-enrolment writes a CITADEL event in addition to the
normal cohort-creation event:

```json
{
  "event_type":     "cyberpath.incident_triggered_enrollment",
  "subject":        "cohort:<cohort_id>",
  "verdict":        "enrolled",
  "categories":     ["nis2.art21.g", "irflow.incident_response"],
  "patterns":       ["incident:<incident_id>", "trigger:<trigger_id>"],
  "tenant":         "<tenant id>",
  "timestamp":      "2027-08-14T16:45:03Z",
  "correlation_id": "<uuid>",
  "project_id":     "<configured project id>",

  "cyberpath": {
    "trigger_id":          "cpt_2027_08_14_00031",
    "incident_id":         "inc_2027_08_14_004",
    "incident_type":       "phishing",
    "incident_severity":   "P2",
    "tracks_assigned":     ["phishing-recognition"],
    "enrolled_user_count": 3,
    "mode":                "auto_enrol",
    "evidence_hash":       "blake3:<hex>"
  }
}
```

This closes the loop end-to-end: an auditor can start from a NIS2
inspection, follow the `cyberpath.completion` events, jump to the
`cyberpath.incident_triggered_enrollment` event via the trigger
id, and from there cross-walk to the IRFlow incident record. The
`cyberpath.incident_remediation_completed` outbound event is
itself recorded as a regular sent-webhook audit row in CyberPath's
DB (not separately emitted to CITADEL — the underlying
`cyberpath.completion` event is the canonical evidence).

See [nis2-evidence-flow.md](./nis2-evidence-flow.md) for the full
audit chain.

## Privacy

`affected_users` from IRFlow is treated as PII-equivalent on the
inbound side. CyberPath persistence rules:

- The user ids themselves already exist in CyberPath's `users`
  table — no new PII is created by the trigger.
- Only the `incident_id` and `trigger_id` are persisted as
  cross-references on cohorts and progress rows. **No incident
  metadata is persisted** — not the title, not the type, not the
  severity (those flow only through the CITADEL audit event,
  which is the system of record for that data).
- The optional CITADEL `tenant` field carries the tenant id, not
  any user-identifying string.
- DLQ entries scrub the JSON body to retain only the trigger id,
  event id, and HTTP status — never the affected user list.

If a user opts out under GDPR Art. 17 (right to erasure),
CyberPath's standard erasure procedure (operator handbook)
nullifies the user's row but does not touch the CITADEL ledger
entries — those are immutable by design and are covered by the
NIS2-evidence-retention legal basis (Art. 21(2)(g)) which overrides
GDPR erasure for the duration of the retention window.

## Configuration

```bash
# Inbound from IRFlow
CYBERPATH_IRFLOW_KEY_SECRET=<64-byte random — matches IRFlow side>
CYBERPATH_IRFLOW_CLOCK_SKEW=5m

# Outbound to IRFlow
CYBERPATH_IRFLOW_API_URL=https://irflow.internal:8085
CYBERPATH_IRFLOW_OUTBOUND_KEY_SECRET=<separate secret per ecosystem rule>

# Behavioural toggles
CYBERPATH_IRFLOW_AUTOENROL=false
CYBERPATH_IRFLOW_RETRAINING_SLA=14d
CYBERPATH_IRFLOW_MAX_TRIGGER_USERS=100
CYBERPATH_IRFLOW_TRACK_MAPPING=/etc/cyberpath/irflow-mapping.yaml
```

Empty `CYBERPATH_IRFLOW_KEY_SECRET` → the inbound endpoint returns
**503**. Empty `CYBERPATH_IRFLOW_OUTBOUND_KEY_SECRET` → outbound
events are queued but never sent (loud WARN at startup); the
incident-remediation feedback loop is dark until configured. This
is fail-closed by design and matches the IRFlow webhook spec's
own posture.

## Metrics

| Metric | Purpose |
|---|---|
| `cyberpath_irflow_trigger_total{result,mode}` | Inbound trigger outcomes |
| `cyberpath_irflow_trigger_latency_seconds` | Trigger handling latency |
| `cyberpath_irflow_outbound_total{result}` | Outbound `cyberpath.incident_remediation_completed` outcomes |
| `cyberpath_irflow_dlq_depth` | DLQ depth (alert > 10 sustained) |
| `cyberpath_irflow_skipped_total{reason}` | Why users were skipped (already_enrolled, opted_out, cert_still_valid, unknown_user) |

## See also

- [architecture.md](./architecture.md) — overall topology
- [citadel-integration.md](./citadel-integration.md) —
  `cyberpath.completion` event the outbound webhook references
- [nis2-evidence-flow.md](./nis2-evidence-flow.md) — full audit
  chain including the trigger event
- [module-list.md](./module-list.md) — track slugs used in the
  type → track mapping
- [../../irflow/docs/webhook-spec.md](../../irflow/docs/webhook-spec.md)
  — the canonical HMAC pattern this doc inherits
- [../../vertguard/docs/threatflow-integration.md](../../vertguard/docs/threatflow-integration.md)
  — sibling reference for the same HMAC + retry + DLQ pattern
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
