# NIS2 Compass — Article 23 Incident Reporting

This document describes the incident-timer subsystem: how NIS2 Compass
tracks the EU NIS2 Directive (2022/2555) Article 23 incident-reporting
deadlines for a "significant incident", and how to use the API.

---

## The legal requirement

Article 23 requires essential and important entities to report a
**significant incident** to their CSIRT or competent authority against
three deadlines, all measured from the moment the entity **became aware**
of the incident:

| Obligation | Deadline | Content |
|---|---|---|
| Early warning | Within **24 hours** | Whether the incident is suspected to be caused by unlawful/malicious acts, or could have a cross-border impact |
| Incident notification | Within **72 hours** | Updates/confirms the early warning; an initial assessment (severity, impact, indicators of compromise where available) |
| Final report | Within **1 month** of the incident notification | Detailed description, root cause, mitigation measures taken, cross-border impact where relevant |

**Significance.** Article 23 obligations apply only to a *significant*
incident. Article 23(3) defines that as an incident that either:

- (a) has caused, or is capable of causing, severe operational disruption
  of the services, or financial loss, for the entity concerned; or
- (b) has affected, or is capable of affecting, other natural or legal
  persons by causing considerable material or non-material damage.

NIS2 Compass stores this as an explicit `significant` boolean on the
`Incident` record — it is a judgement call the reporting organisation
makes, not something derived automatically from `severity` (a critical
internal-only incident may not meet the Article 23(3) bar, and a
medium-severity incident with third-party impact may).

---

## Data model

- **`Incident`** (`incidents` table) — one row per tracked incident: the
  organisation it belongs to, `detected_at` (the single timestamp that
  starts all three clocks), `severity`, `status`
  (`active`/`contained`/`resolved`), `resolved_at`, and `significant`.
- **`IncidentReport`** (`incident_reports` table) — one row per
  `(incident_id, report_type)`, where `report_type` is one of
  `early_warning`, `notification`, `final_report`. All three rows are
  created automatically when an incident is created. `submitted_at` /
  `submitted_by` / `content` record whether and when each obligation was
  actually discharged.

**Deadlines are computed, not stored.** `early_warning_due_at`,
`notification_due_at`, and `final_report_due_at` are never persisted as
independent columns — they are pure functions of `detected_at` (and, for
the final report, `resolved_at`), computed on every read in
`app/incident_timers.py`. This is deliberate: a stored deadline column
could silently drift from `detected_at` if the latter were ever corrected,
and a stored *status* (on-track/overdue/etc.) would need a background job
constantly rewriting it to stay accurate against wall-clock time. See the
docstrings in `app/incident_timers.py` and `app/models.py` for the full
reasoning.

`detected_at` is immutable after creation via the API (`PATCH
/incidents/{id}` rejects any attempt to change it) for the same reason:
every deadline and every `IncidentReport.due_at` is derived from it, so
changing it after reports may already have been filed would retroactively
rewrite whether those submissions were on time.

---

## API

Full request/response shapes are in [api-reference.md](api-reference.md).
Summary:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/organisations/{org_id}/incidents` | Create an incident (starts the clocks) |
| `GET` | `/api/v1/organisations/{org_id}/incidents` | List incidents for an organisation, with live per-deadline status |
| `GET` | `/api/v1/incidents/{id}` | Get one incident + live per-deadline status |
| `PATCH` | `/api/v1/incidents/{id}` | Update severity/status/significant/title/description |
| `POST` | `/api/v1/incidents/{id}/reports/{report_type}` | Submit a report against one deadline |
| `GET` | `/api/v1/incidents/at-risk` | Cross-organisation list of incidents with an approaching/missed deadline |

### Per-deadline status

Every `IncidentReport` serialisation includes a live-computed `status`,
one of:

| Status | Meaning |
|---|---|
| `on_track` | Not yet submitted; deadline comfortably in the future |
| `due_soon` | Not yet submitted; deadline within the warning window (6 hours by default) |
| `overdue` | Not yet submitted; deadline has passed |
| `met` | Submitted at or before its deadline |
| `missed` | Submitted after its deadline |

### Report submission rules

`POST /incidents/{id}/reports/{report_type}` enforces two rules, both
documented inline in `app/api/incidents.py`:

1. **Write-once.** A report type can only be submitted once. Re-submitting
   an already-filed report is rejected (`409 CONFLICT`) — `submitted_at`
   is the compliance fact auditors and CITADEL rely on, so it cannot be
   silently overwritten.
2. **Sequential.** `notification` cannot be submitted before
   `early_warning`, and `final_report` cannot be submitted before
   `notification` (`409 OUT_OF_ORDER`) — this mirrors how Article 23
   defines the obligations (the notification "updates and, where
   necessary, confirms" the early warning; the final report follows the
   notification). There is deliberately **no** rule against submitting a
   report *before* its own deadline — Article 23 sets maximum deadlines,
   not minimum ones, and an organisation should always be free to report
   early.

`submitted_at` is always set from server time, never accepted from the
request body — a client-supplied timestamp would let a late report be
backdated to falsely appear on time.

### Governance

Submitting an Article 23 report is a regulatory attestation, so it is
routed through CITADEL MARSHAL the same way a control-compliance
attestation is (see the [CITADEL Governance & Audit](../README.md#citadel-governance--audit)
section of the main README) — a `REFUSE`/`HARD_STOP` verdict blocks the
submission. If `CITADEL_API_URL` is not set, this is a no-op and behaves
exactly as it did before CITADEL was wired in.

### Monitoring / alerting

`GET /api/v1/incidents/at-risk` returns incidents (restricted to
organisations the caller owns, and to `significant` incidents only) whose
next unfilled deadline is `due_soon` or `overdue`, sorted by due date.

**Why an endpoint and not a background job:** NIS2 Compass has no task
queue or scheduler of its own (there is no Celery/APScheduler/cron
anywhere in this platform — the closest existing mechanism,
`app/notifications.py`, only fires synchronously on state changes an API
caller triggers, it does not periodically re-check time-based deadlines).
Rather than build a new in-process scheduling framework for this one
feature, `/incidents/at-risk` is designed to be cheap and safe to poll on
a schedule by an external cron job or monitoring/alerting integration.
This is a deliberate, documented scope decision, not a silently
half-finished feature.

---

## Known limitations

**The Article 23(4) ongoing-incident extension is only partially
implemented.** If a significant incident is still ongoing when the
primary final-report deadline (one month after the notification deadline)
arrives, Article 23 requires the entity to submit an **interim progress
report** at that point instead, with the true final report then due **one
month after the incident is actually resolved**.

This subsystem implements the primary 3-deadline path
(`early_warning` / `notification` / `final_report`, all keyed off
`detected_at`) in full, including on-time/missed tracking and monitoring.
Of the extension, it implements only the piece that needed no additional
state: `Incident.resolved_at` re-bases `final_report_due_at` to one month
after actual resolution when resolution happens after the primary due
date (`incident_timers.final_report_due_at`).

**What is not implemented:** a distinct `interim_progress_report`
obligation/report_type, and any automatic detection of "the incident is
still open at the primary final-report due date, so surface an interim
report requirement." An organisation in that situation must, today,
identify it manually (the `final_report` row will simply show as
`overdue` at the primary due date if the incident is still `active` or
`contained`) and submit its interim progress report to the competent
authority through whatever channel it uses outside this system, while
relying on this subsystem's re-based `final_report_due_at` for the
eventual true final-report deadline once the incident is marked
`resolved`.

**The "one month" window is approximated as a fixed 30-day period**, not
calendar-month arithmetic (no `python-dateutil` dependency exists in this
project today). This is conservative for every 31-day month (the computed
deadline is *earlier* than a strict calendar-month reading, never later)
and up to 1–2 days later than a strict calendar-month reading for
February. See the comment on `FINAL_REPORT_WINDOW` in
`app/incident_timers.py` for the full analysis.
