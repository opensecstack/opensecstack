# CyberPath Instructor Handbook

> Guide for human instructors using the CyberPath platform —
> classroom trainers, NIS2 compliance officers running internal
> awareness programmes, security-team leads onboarding new hires.
> If you author content as well, also read
> [./track-content-guide.md](./track-content-guide.md) and
> [./lab-content-guide.md](./lab-content-guide.md).
>
> Status: design intent for v1.0.0 capabilities. v1.0.0 ships a
> reduced subset (no certification, no WORM evidence, no cohort
> reporting); the v1.0.0 fields and screens noted below land
> incrementally between v0.5.0 and v1.0.0.

CyberPath is built so an instructor's job is to *coach* the learners
and *attest* to the cohort's progress, not to chase grading. The
platform handles the audit-grade record-keeping; the instructor
handles the human side.

## Instructor role and permissions

The `instructor` role is provisioned by the deployment's identity
admin. Permissions:

| Capability | Granted | Notes |
|---|:-:|---|
| Author / edit tracks (PR-based) | yes | Subject to two-eyes review |
| Review track PRs | yes | Bound by CODEOWNERS |
| Create cohorts | yes | Within own tenant |
| Enroll learners into cohorts | yes | Up to `INSTRUCTOR_MAX_COHORT_SIZE` |
| View cohort progress dashboard | yes | Cohort scope only — not other instructors' cohorts |
| Manually grade quiz/lab attempts | yes | Logged with reason in audit trail |
| Override certification issuance | yes | Logged with reason; sealed in CITADEL |
| Revoke a certification | yes | Logged with reason; sealed in CITADEL |
| Edit another instructor's cohort | no | Use co-instructor role for shared cohorts |
| Issue platform-wide announcements | no | Platform admin only |

The override-and-revoke paths exist because edge cases happen
(disability accommodation, equipment failure mid-lab, a question
later found to have an ambiguous correct answer). Every override
writes a `cyberpath.completion.override` event into CITADEL with the
free-text reason, the original auto-grade outcome, and the
instructor's identity.

## Cohort management

A *cohort* is a group of learners moving through one or more tracks
on a shared schedule. Typical cohorts: a quarterly NIS2 awareness
intake, a developer team going through Secure Coding, a SOC team
running monthly Threat Intel basics refreshers.

### Create a cohort

```
Dashboard → Cohorts → New cohort

Name:           "NIS2 Awareness — 2027 Q2 intake"
Description:    "Mandatory baseline for new staff."
Tracks:         [nis2-article-21-awareness, phishing-recognition]
Start date:     2027-04-15
Target end:     2027-05-15
Co-instructors: [arta.k@example.gov]
Visibility:     tenant-internal
```

Or via API:

```bash
curl -X POST https://cyberpath.internal:8086/api/v1/cohorts \
  -H "Authorization: Bearer <instructor token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name":         "NIS2 Awareness — 2027 Q2 intake",
    "tracks":       ["nis2-article-21-awareness", "phishing-recognition"],
    "starts_at":    "2027-04-15T00:00:00Z",
    "target_end":   "2027-05-15T00:00:00Z"
  }'
```

### Enroll learners

Bulk enroll by CSV (`email,display_name`) or via the dashboard's
multi-select. Enrolment honours track prerequisites by default —
a learner missing Track 1 cannot be enrolled in Track 2 unless the
instructor explicitly waives the prerequisite (logged).

### Monitor progress

The cohort dashboard surfaces:

- Per-learner progress bar across the cohort's tracks
- Last-activity timestamp
- Quizzes passed / failed
- Lab attempts with pass/fail outcome
- Time-to-complete distribution vs the track's authored estimate
- Drop-off points: which lesson, on average, learners stall on

A learner who hasn't logged in for 7+ days is flagged with a yellow
chip; 14+ days is red. Use this to drive your follow-up rather than
counting badges.

## Live session integration (placeholder for v1.1+)

In v1.0.0, instructors run live sessions on whatever conferencing
platform they already use (Zoom, Teams, Jitsi). The platform records
the session via webhook:

```bash
# Configure a webhook target in the cohort settings
POST /api/v1/cohorts/{id}/sessions/webhook
{
  "url":     "https://zoom.example/webhook/...",
  "secret":  "<HMAC secret>"
}
```

The webhook payload (attendance, recording URL, duration) is stored
on the cohort timeline so audit reports can reference live-session
participation alongside platform completions. Native conferencing
(scheduled rooms inside the platform) is a v1.1+ candidate; do not
plan around it for v1.0.0.

## Grading

CyberPath grades automatically by default. The exceptions:

### Auto-graded

- Multiple-choice, true-false, code-fill, scenario quiz questions
- Lab validation rules (deterministic; see
  [./lab-content-guide.md](./lab-content-guide.md))

### Manual review

Instructors can opt a quiz or lab into manual review by setting
`requires_manual_review: true` on the quiz/lab in the cohort
configuration. Use this for:

- Open-ended scenario questions where the rubric is judgement-based
- Pilot tracks where the auto-grader is being calibrated
- Disability accommodations on a specific learner basis

The review queue surfaces submissions with:

- Learner identity
- Submission timestamp + time-on-task
- Auto-grader's tentative score (if any)
- The full submitted artefact (quiz answers, lab snapshot)

### Rubric editor

For manual review of scenario answers, the rubric editor lets the
instructor define partial-credit dimensions:

```yaml
# cohort-config.yaml — rubric override
rubric:
  scenario-q4:
    dimensions:
      - id:     identifies-out-of-band-verification
        max:    2
      - id:     names-correct-channel
        max:    1
      - id:     escalation-path-correct
        max:    1
    pass_threshold: 3
```

Partial credit is permitted up to each dimension's `max`. The
graded result and the per-dimension breakdown become part of the
completion record.

## Certification issuance

### Automatic

A certification is issued automatically when a learner:

1. Completes every lesson in the track,
2. Passes every quiz at or above its `pass_threshold`,
3. Passes every lab against its `success_criteria`,
4. Has no in-flight manual reviews outstanding.

The platform signs the certification (Ed25519), emits a
`cyberpath.completion` event to CITADEL, and exposes the certificate
PDF via the learner's dashboard. The instructor sees a notification.

### Override path

Sometimes a certification needs to be issued despite an
edge-case fail (lab timed out due to platform incident; assistive-
tech compatibility issue; documented learner accommodation). The
instructor opens the learner's cohort record, clicks **Issue with
override**, and provides:

- Reason (free text, mandatory, ≥ 30 characters)
- Override category (one of: `platform-incident`,
  `accommodation`, `content-defect`, `other`)
- Linked artefacts (e.g. incident ticket, accommodation document
  reference)

The override is sealed into CITADEL alongside the certification with
the same `cyberpath.completion.override` event referenced above.
Auditors see *both* the override reason and the original auto-grade
outcome — overrides are visible, not hidden.

### Revocation

Revocation is the inverse: the instructor opens the certificate,
clicks **Revoke**, provides reason + category. The certificate
remains visible in audit history (because CITADEL is WORM) but is
flagged `revoked` and excluded from `coverage` queries. Use cases:
later-discovered cheating; track found to have a content defect that
invalidates prior issuances.

## Reporting

### Per-cohort completion report

```
Dashboard → Cohorts → {cohort} → Reports → Completion
```

Or:

```bash
curl -sf https://cyberpath.internal:8086/api/v1/cohorts/{id}/report/completion \
  -H "Authorization: Bearer <instructor token>" \
  -o cohort-completion-2027Q2.pdf
```

The PDF includes per-learner outcomes, per-track pass rates, the
content versions completed against, the WORM entry ids, and the
signing key fingerprint — everything an internal compliance review
or external NIS2 auditor needs in one bundle.

### Per-track effectiveness

Aggregate analytics across all cohorts running a given track:

- Average time-to-complete vs authored estimate
- Pass rate per quiz and per question
- Lab failure clustering (which validation rule fails most often)
- Drop-off lessons

Use this to drive content revisions. A question with a 95% pass rate
is probably too easy; a question with a 30% pass rate is either
genuinely hard or poorly worded — inspect.

### Drop-off analysis

For any cohort, the drop-off chart shows which lesson learners stop
at. Combine with the live-session attendance data from the webhook
to triage: did learners drop off after a session they didn't attend?

### NIS2 audit-ready PDF export

```bash
cyberpath-cli evidence export \
  --cohort {cohort_id} \
  --from   2027-04-01 \
  --to     2027-05-31 \
  --format audit-bundle \
  --output /secure/cyberpath-evidence-2027Q2.tar.gz
```

The bundle is signed and contains: cohort definition, enrolment
list, per-learner completions, content_hashes referenced, CITADEL
WORM entry ids, certification signatures, and the platform's Ed25519
public key for verification. Hand this to your auditor.

## Common workflows

### Onboarding 50 staff for NIS2 Article 21 awareness

1. Create cohort "NIS2 Awareness — {YYYY-Qn}".
2. Enroll the 50 staff via CSV.
3. Set start date; target end 4 weeks out.
4. Optional: schedule a live kick-off session, register the webhook.
5. Monitor dashboard; nudge red-flagged learners weekly.
6. At target end + 1 week, export the audit bundle.

### Monthly skills assessment

1. Create cohort "Phishing recognition — {YYYY-MM} refresher".
2. Enroll the SOC team.
3. Track 2 only, 1-week schedule.
4. Compare completion times against last month's cohort to spot
   drift.

### Post-incident retraining (linked to IRFlow)

When IRFlow surfaces an incident with a *root cause* of insufficient
training, it can recommend a CyberPath track. Workflow:

1. IRFlow → cohort recommendation arrives in the instructor inbox.
2. Instructor reviews scope (which staff, which track).
3. Click **Create cohort from incident** — pre-populates name,
   tracks, and learners (those involved in the incident response).
4. Add a cohort-level note linking to the IRFlow incident id.
5. The completion bundle for this cohort cross-references the
   incident in CITADEL — closing the loop on "what training would
   have prevented this, and have those people now had it?"

## Anti-cheat hooks

CyberPath is not a proctored-exam platform (see
[../ROADMAP.md § Non-goals](../ROADMAP.md)). It does, however,
collect signals that a competent reviewer can use to spot likely
cheating:

- **Time tracking**: per-question and per-lab time-on-task. A learner
  who answers a 5-minute question in 4 seconds is flagged.
- **Anomalous answer-pattern detection** (designed-for, not enforced
  in v1.0.0): learners with identical answer sequences across
  randomised quizzes get cluster-flagged in the report.
- **Lab snapshot diffing**: identical sandbox snapshots across two
  learners in the same cohort flag.
- **Replay**: every lab session has a deterministic replay (assets,
  validation, snapshot). An instructor can re-run a suspect
  submission against the same fixture.

These hooks surface *suspicions*, not verdicts. Investigation +
human judgement is on the instructor. The override / revocation
paths above are how confirmed findings flow back into the audit
record.

## See also

- [./track-content-guide.md](./track-content-guide.md) — authoring tracks
- [./lab-content-guide.md](./lab-content-guide.md) — authoring labs
- [./operator-handbook.md](./operator-handbook.md) — operator-side
- [./architecture.md](./architecture.md) — completions and certifications schema
- [./citadel-integration.md](./citadel-integration.md) — completion event schema
- [./nis2-integration.md](./nis2-integration.md) — coverage API
- [../ROADMAP.md](../ROADMAP.md) — Phase 2 deliverables
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — community PR process
