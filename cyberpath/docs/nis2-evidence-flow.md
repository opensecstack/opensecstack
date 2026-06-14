# NIS2 Evidence Flow — Article 21(2)(g) Audit Trail

> End-to-end documentation of the cryptographically-verifiable
> training audit trail CyberPath produces for NIS2 inspectors. Lands
> with v1.0.0.
>
> Read this alongside [citadel-integration.md](./citadel-integration.md)
> (the wire contract for `cyberpath.completion`) and
> [nis2-integration.md](./nis2-integration.md) (the NIS2 Compass
> coverage / recommend API).

## Why this doc exists

NIS2 Article 21(2)(g) requires entities to implement *"basic cyber
hygiene practices and cybersecurity training"*. Article 21(2)(h)
adds *"policies and procedures regarding the use of cryptography
and, where appropriate, encryption"*. When a national CSIRT or
sectoral regulator inspects a NIS2-scope entity, they will not
accept a screenshot of an LMS dashboard. They want an **immutable
trail** showing:

- WHO completed WHAT training
- WHEN, on which exact content version
- with cryptographic proof the record has not been altered

CyberPath's job is to produce that trail in a form an auditor can
verify months or years after the fact, without depending on
CyberPath being online or unmodified at audit time. The components
below give the regulator a chain of evidence that bottoms out in
CITADEL's WORM ledger.

This document is the index that ties those components together.

## Trail components

The audit trail is composed of six discrete artefacts. Each is
captured at a specific point in the learner journey and each
references the next one by hash, so the chain is verifiable end-to-
end without re-querying CyberPath.

| # | Component | Source | What it proves |
|:-:|---|---|---|
| 1 | **User identity** | signed JWT issued by the deployment auth provider | the learner is who they claim to be (subject + tenant binding) |
| 2 | **Track content snapshot** | `content_versions.content_hash` (BLAKE3 over canonical lesson markdown) | the learner saw exactly this content; immutable per-revision |
| 3 | **Quiz submissions** | per-question SHA-256 of `(question_id || answer_value)` | the learner answered specific questions a specific way |
| 4 | **Lab session log** | signed, hash-chained command transcript (`lab_sessions.evidence_hash`) | which commands the learner ran, in order, with timing |
| 5 | **Completion event** | row in `completions` (server-clock timestamp + Ed25519 signature over the canonical body) | the platform asserts completion |
| 6 | **CITADEL WORM entry** | `cyberpath.completion` event in CITADEL's append-only ledger | independent immutable witness; survives CyberPath compromise |

Components 1–4 live in CyberPath's PostgreSQL. Component 5 also
lives in PostgreSQL but is signed with the platform's Ed25519
certification key (rotated per the operator handbook). Component 6
is the load-bearing one for audit: even if CyberPath's database is
tampered with, the CITADEL ledger entry stands.

## End-to-end flow

```
   ┌──────────┐    ┌────────────┐    ┌────────────┐    ┌──────────┐
   │ Cohort   │───►│ User       │───►│ Lessons    │───►│ Quiz     │
   │ created  │    │ starts     │    │ completed  │    │ passed   │
   └────┬─────┘    │ track      │    │ (aggregate)│    └────┬─────┘
        │          └─────┬──────┘    └────────────┘         │
        │                │                                  │
   CITADEL          progress row              cyberpath.quiz_passed
 cohort_created      inserted                  (CITADEL, low-prio)
                                                            │
                                                            ▼
   ┌──────────┐    ┌────────────┐    ┌────────────┐    ┌──────────┐
   │ Lab      │───►│ Track      │───►│ Cert       │───►│ Auditor  │
   │ session  │    │ completion │    │ issued     │    │ query    │
   │ ends     │    │ (all gates)│    │            │    │ (months) │
   └────┬─────┘    └─────┬──────┘    └────┬───────┘    └────┬─────┘
        │                │                 │                │
  cyberpath.       cyberpath.        DB row +         CITADEL filter
  lab_completed    completion        WORM entry       + content
  (CITADEL)        (WORM)            optional PDF     verification
```

### Step by step

1. **Cohort created.** An admin creates a cohort against a track
   (e.g. *Phishing recognition* for the Q3 onboarding wave).
   CyberPath emits `cyberpath.cohort_created` to CITADEL, capturing
   the cohort id, track id + version, intended user list, and
   creator identity.

2. **User starts track.** A row is inserted in `progress` with
   `started_at` and the `content_version_id` pinned for the user's
   first lesson. CyberPath emits a low-priority
   `cyberpath.track_started` event (audit-only; does not block).

3. **Per lesson completed.** `progress` is updated. **No CITADEL
   emit per lesson** — lessons are high-volume (a single track may
   have 30+ lessons). Lesson-level evidence is rolled up into the
   completion event in step 6. Per-lesson hashes are still
   recorded in the `completions` rows so the rollup can be
   recomputed.

4. **Quiz passed.** When a learner passes a quiz (>= the track's
   `pass_threshold`), CyberPath emits `cyberpath.quiz_passed` with
   the score, content version, and the answer-hash list. This is
   the smallest unit of evidence regulators ask for individually
   ("did this user pass the phishing-recognition quiz?").

5. **Lab session ends.** The xterm.js / wasmtime session writes a
   command-by-command transcript. On session end the transcript is
   hash-chained (each line's hash references the prior), the chain
   tip is signed, and `lab_sessions.evidence_hash` is set.
   `cyberpath.lab_completed` is emitted to CITADEL with the chain
   tip hash (not the transcript itself — see Privacy below).

6. **Track completion.** When all gates for a track pass (every
   required lesson, quiz, and lab marked complete with the right
   versions), the `internal/path/` module assembles the canonical
   completion body, BLAKE3-hashes it, signs with Ed25519, and
   inserts a `completions` row. `internal/citadel/` then emits
   `cyberpath.completion` — this is the **WORM entry** the auditor
   relies on.

7. **Certification issued.** If the track offers a certification
   (`paths.cert_offered = true`), a `certifications` row is
   inserted with `issued_at`, `expires_at`, and an Ed25519
   signature over the canonical certification body. A second WORM
   entry is emitted with `certification_level: track-cert`. A PDF
   is optionally rendered for the learner.

8. **Auditor query (months later).** See Auditor workflow below.

## Auditor workflow

The auditor flow is intentionally CyberPath-independent: an
auditor with CITADEL read access and the public content endpoint
can verify the trail without any CyberPath admin access.

### Concrete steps

1. **Open the CITADEL UI** (or call the CITADEL events API
   directly).

2. **Filter** by `event_type=cyberpath.completion` plus
   `tenant=<entity-id>` and the inspection time window. Optional:
   filter by `subject=user:<user_id>` for a single-learner audit.

   ```
   GET /events
       ?event_type=cyberpath.completion
       &tenant=acme-energy
       &timestamp_from=2027-01-01T00:00:00Z
       &timestamp_to=2027-12-31T23:59:59Z
   ```

3. **Export** the result list to CSV or PDF (CITADEL's
   export-with-ledger-signature feature; the export carries
   CITADEL's anchor signature, not just a screenshot).

4. **For each completion**, resolve `cyberpath.content_version_id`
   against CyberPath's public read endpoint:

   ```
   GET /api/v1/content/versions/<id>
   → returns canonical lesson markdown + content_hash
   ```

   Re-hash the returned markdown locally and compare to
   `content_hash`. If they match, the content the learner saw is
   exactly what is presented to the auditor.

5. **Re-hash the evidence body** (the canonical body schema is
   public — see the certification appendix in the operator
   handbook). Compare to `cyberpath.evidence_hash` from the
   CITADEL event. If they match, the completion record has not
   been altered.

6. **Verify the Ed25519 signature** in `signed_by` against the
   published platform key. Key rotation history is itself a WORM
   stream; the auditor walks the rotation chain back to the key
   in use at completion time.

### End state

A single PDF report containing:

- the CITADEL-signed completion list
- per-completion content snapshots (re-rendered)
- hash verification results
- signature verification results

This satisfies a NIS2 inspector for Article 21(2)(g) evidence
without requiring CyberPath to be queried at all during the
inspection itself.

## NIS2 measure-to-evidence map

For each Article 21(2) measure, this table lists the CyberPath
tracks (per [module-list.md](./module-list.md)) and event types
that contribute evidence. "Primary" means the track's main
mapping; "secondary" means the track touches the measure but is
primarily aligned elsewhere.

| Measure | Title (abbrev.) | Primary tracks | Secondary tracks | Evidence event |
|:-:|---|---|---|---|
| (a) | Risk analysis & info-sys policies | Track 1 | — | `cyberpath.completion` (categories: `nis2.art21.a`) |
| (b) | Incident handling | Tracks 4, 6, 8 | Track 1 | `cyberpath.completion` (`nis2.art21.b`) |
| (c) | Business continuity | Track 7 | — | `cyberpath.completion` (`nis2.art21.c`) |
| (d) | Supply chain security | Track 5 | — | `cyberpath.completion` (`nis2.art21.d`) |
| (e) | Acquisition / dev / maintenance | Tracks 3, 5 | — | `cyberpath.completion` (`nis2.art21.e`) |
| (f) | Effectiveness assessment | — | — | covered by NIS2 Compass; CyberPath contributes coverage data via `GET /coverage/{user_id}` |
| (g) | **Cyber hygiene + training** | All 8 tracks | — | every `cyberpath.completion` carries `nis2.art21.g` |
| (h) | Cryptography & encryption | Track 7 | — | `cyberpath.completion` (`nis2.art21.h`) |
| (i) | HR & access control awareness | Tracks 1, 2, 6 | — | `cyberpath.completion` (`nis2.art21.i`) |
| (j) | MFA / continuous auth | — | — | not yet covered (Track 9 candidate, post-v1.0) |

For measure (g), specifically: every completion the platform
emits is, by construction, evidence. For measures (b) and (i),
which have multiple track contributors, an auditor wanting full
coverage needs completions from at least one track per measure.

## Retention

Different artefacts have different retention requirements driven
by NIS2 default expectations and cost-of-storage realities.

| Artefact | Retention | Driver |
|---|---|---|
| `completions` rows + `cyberpath.completion` WORM entries | **immutable, kept forever** | legal evidence; certifications reference completion ids; deletion would invalidate downstream certs |
| `certifications` rows + WORM entries | immutable, kept forever | same as completions |
| `content_versions` rows | immutable, kept forever | required to verify completion hashes years later |
| Audit log events (`cyberpath.track_started`, `cyberpath.cohort_created`, etc.) | **7 years** | NIS2 default audit-trail retention |
| Quiz answer hashes | 7 years | match audit-log retention |
| `lab_sessions` command transcripts (raw) | **1 year** | cost; the chain-tip hash in the WORM entry is sufficient for verification — the transcript itself is replay-only |
| `progress` rows (in-flight only) | until completion or 2 years dormant | operational |

The lab transcript retention is the only tradeoff worth flagging:
after 1 year, an auditor cannot replay individual commands, but
the certification's evidence hash still subsumes the transcript
chain tip. Re-running the lab against the snapshotted lab image
(immutable) reproduces the same transcript class — that is the
audit position. Deployers who want transcripts kept longer set
`CYBERPATH_LAB_LOG_RETENTION` to a higher value.

## Privacy

Specific points worth calling out:

- **Quiz contents.** Question text is in the content snapshot
  (already public via the read endpoint). Answer values are
  hashed before being persisted; the raw answers never leave the
  request lifecycle except in the immediate scoring path.

- **Lab transcripts.** Stored locally to CyberPath, not in
  CITADEL. Only the chain-tip hash is emitted. A deployer can
  delete a transcript at the 1-year boundary and the audit chain
  remains valid (because the completion was signed *over* the
  chain tip, not the transcript bytes).

- **Identity.** The CITADEL `subject` field is `user:<user_id>`
  (the platform's stable id, not an email or name). Pseudonym
  resolution is a CyberPath-side join; auditors with sufficient
  authorisation perform it through the operator handbook flow.

## Out of scope

- **NIS2 Article 23 incident notification.** That flows through
  IRFlow + NIS2 Compass, not CyberPath. CyberPath only contributes
  retraining evidence post-incident — see
  [irflow-integration.md](./irflow-integration.md).

- **ENISA ECSF competence framework alignment.** v1.1+ deliverable.
  The current measure mapping is to NIS2 Article 21(2) directly.

- **Cross-jurisdiction reporting** (e.g. mapping NIS2 evidence to
  GDPR Art. 32 or DORA equivalents). Each regulator's mapping is
  a deployer-side concern; CyberPath emits the raw evidence and
  NIS2 Compass / equivalent tooling does the mapping.

- **Bulk export to a third-party LMS.** Not supported. CyberPath
  is the system of record for the evidence it produces.

## See also

- [architecture.md](./architecture.md) — overall topology and
  schema
- [citadel-integration.md](./citadel-integration.md) —
  `cyberpath.completion` wire contract
- [nis2-integration.md](./nis2-integration.md) — NIS2 Compass
  coverage + recommend API
- [module-list.md](./module-list.md) — the 8 tracks and the NIS2
  Article 21 measure coverage matrix
- [irflow-integration.md](./irflow-integration.md) — incident-
  driven retraining flow
- [../../citadel/docs/worm-log.md](../../citadel/docs/worm-log.md)
  — CITADEL WORM ledger semantics
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
