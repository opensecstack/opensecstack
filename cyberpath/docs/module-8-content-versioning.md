# Module 8: Content Versioning

> Status: design intent for v1.0.0. Implementation lives in
> `internal/content/`. This module is the gatekeeper for all content
> mutations; changes to lesson text, quiz banks, and lab images must
> flow through it to preserve the audit invariant that every
> completion record references the exact content revision the learner
> saw.

## Overview

The Content Versioning module ensures that lesson content is
immutably snapshotted at publish time, that every completion record
references a specific snapshot, and that learners mid-track are not
silently served different content than what they started with.

The load-bearing invariant, stated in `architecture.md`:

> `completions.content_version_id` is the load-bearing audit field —
> every completion references the exact lesson revision the learner
> saw. Module 8 enforces that revisions are append-only.

This invariant makes CyberPath evidence NIS2-audit-grade: a regulator
can reproduce which specific content a learner completed, as of which
date.

## Content versioning model

Content is versioned at the **lesson** level. A lesson may have many
content versions over time; the current published version is the one
pointed to by `lessons.content_version_id`.

Versions are **append-only**. No version row is ever deleted or
updated after creation. A "content change" means a new version row
is inserted and `lessons.content_version_id` is updated to point to
it. The old rows remain and are referenced by historical completions.

### Semantic versioning for content

Each content version has a semver string (`revision` column). The
versioning conventions:

- **Patch** (e.g. `1.0.0` → `1.0.1`): Typo fixes, formatting,
  clarifications that do not alter the instructional substance or
  quiz/lab answers. No re-completion required from active learners.
- **Minor** (e.g. `1.0.0` → `1.1.0`): New examples, expanded
  coverage, additional quiz questions added. Quiz and lab pass
  criteria unchanged. Re-completion is at the operator's discretion
  (`require_recompletion: false` by default).
- **Major** (e.g. `1.0.0` → `2.0.0`): Instructional substance
  changed, quiz answers changed, lab scenario changed, or NIS2
  measure mapping changed. Re-completion is required by default
  (`require_recompletion: true`).

The `require_recompletion` flag can be overridden per-publish by the
content author. The override is intentional: a patch that fixes a
factually incorrect quiz answer still constitutes a patch-level change
in intent but may require re-completion for integrity reasons.

### Content hash

`content_versions.content_hash` is the BLAKE3 hash of the canonical
content body for the lesson at that revision. The canonical body is:

```
BLAKE3(
  lesson_markdown_bytes_sq ||
  lesson_markdown_bytes_en ||
  quiz_yaml_bytes           ||  (empty if no quiz)
  lab_yaml_bytes                ||  (empty if no lab)
)
```

Byte streams are concatenated in that fixed order with no separator.
This hash is reproducible from the source files at any point in time.
The `make test-content` target verifies that the hash in the database
matches the hash of the source files on disk.

Lab images are not included in the content hash directly — instead,
`lab_definitions.image_digest` (the OCI digest) is stored alongside
and cross-referenced. A lab image change without a lesson content
version bump is a content error caught by `make test-content`.

## Database schema

### `content_versions`

```sql
CREATE TABLE content_versions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lesson_id      UUID NOT NULL REFERENCES lessons(id) ON DELETE RESTRICT,
    revision       TEXT NOT NULL,           -- semver string, e.g. "1.2.0"
    content_hash   TEXT NOT NULL,           -- BLAKE3 hex
    require_recompletion BOOLEAN NOT NULL DEFAULT false,
    change_summary TEXT,                    -- human-readable, for audit log
    published_by   UUID REFERENCES users(id),
    published_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (lesson_id, revision)
);
```

`ON DELETE RESTRICT` on `lesson_id` ensures a lesson cannot be
deleted while content versions reference it. Content removal is a
manual, multi-step operation with an operator runbook.

### Foreign key on `lessons`

```sql
ALTER TABLE lessons
    ADD COLUMN content_version_id UUID NOT NULL REFERENCES content_versions(id);
```

This column always points to the current published version. It is the
only mutable reference into `content_versions`; everything else
(completions, progress) references content versions by direct UUID
and is frozen at the time of the event.

### `content_version_events`

```sql
CREATE TABLE content_version_events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lesson_id          UUID NOT NULL REFERENCES lessons(id),
    old_version_id     UUID REFERENCES content_versions(id),
    new_version_id     UUID NOT NULL REFERENCES content_versions(id),
    require_recompletion BOOLEAN NOT NULL,
    active_enrolments  INTEGER NOT NULL,    -- snapshot at publish time
    event_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by       UUID REFERENCES users(id)
);
```

This table is the change log. It answers "when did this lesson's
content change, who published it, and how many learners were
mid-lesson at that moment?"

## Publish workflow

Content changes go through the publish workflow, not direct SQL
edits. The workflow is:

1. Content author opens a PR against the `content/` directory.
2. `make test-content` runs in CI: validates `track.yaml`, verifies
   bilingual coverage, checks that `content_hash` matches the source
   files for any modified lessons.
3. PR is reviewed (subject-matter peer + at least one maintainer).
4. On merge, the `content-publisher` CI job runs:
   a. Inserts a new `content_versions` row for each modified lesson.
   b. Updates `lessons.content_version_id` for each modified lesson.
   c. Inserts a `content_version_events` row for each change.
   d. If `require_recompletion: true` for any changed lesson, triggers
      the re-completion notification flow (see below).
5. The API's in-memory prerequisite cache is invalidated via a
   `LISTEN/NOTIFY` signal on the `content_version_published` channel.

The content-publisher job runs with a dedicated service account that
has `INSERT` on `content_versions` and `UPDATE` on
`lessons.content_version_id` — no broader write access.

## Active enrolment handling

When a lesson's content version changes while learners have active
`progress` rows for that lesson, the platform must make a choice for
each affected learner. Module 8 evaluates three cases:

### Case 1: Patch-level change, `require_recompletion: false`

No action. The learner's existing `progress` row continues. When they
call `mark_complete`, the completion is recorded against the new
`content_version_id` (the current published version at the time of
completion). The old version they read is acknowledged in
`content_version_events.old_version_id`.

This is acceptable for patch changes because the instructional
substance is unchanged.

### Case 2: Minor or major change, `require_recompletion: false`

The learner is shown a non-blocking notification on next lesson load:
"The content for this lesson has been updated. You may continue with
your current session." The completion is recorded against the new
version.

### Case 3: Major change, `require_recompletion: true`

The learner's `progress` row for the lesson is marked
`requires_restart` (new status value). On next lesson load, the
learner sees a blocking message: "This lesson's content has been
updated in a way that requires you to restart it. Your progress to
this point is saved." Their `progress.started_at` is reset to now;
`progress.last_seen_at` is preserved for record-keeping.

If the learner had already completed the lesson (a `completions` row
exists), the completion is not invalidated — historical evidence is
never mutated. However, if the track requires re-completion for
NIS2 evidence purposes, the operator must configure
`CYBERPATH_CERT_RECOMPLETION_INVALIDATES_CERT=true`, which marks the
existing certificate as `requires_renewal` (not revoked — it
remains valid, but the NIS2 evidence export flags it as potentially
stale).

## Migration when content changes under active enrolments

The migration is run as a database transaction by the
`content-publisher` job immediately after inserting the new version:

```sql
-- internal/content/migrate.go (design intent)
BEGIN;

-- 1. Insert the new content version (done by publisher job)
-- 2. Update the lesson pointer
UPDATE lessons SET content_version_id = $new_version_id WHERE id = $lesson_id;

-- 3. Log the event
INSERT INTO content_version_events (...) VALUES (...);

-- 4. Mark affected progress rows if require_recompletion
UPDATE progress
    SET requires_restart = true
    WHERE lesson_id = $lesson_id
      AND $require_recompletion = true;

-- 5. Mark affected certifications as requires_renewal if configured
-- (only if CYBERPATH_CERT_RECOMPLETION_INVALIDATES_CERT = true)
UPDATE certifications
    SET requires_renewal = true
    WHERE path_id = $path_id
      AND $require_recompletion = true
      AND $cert_invalidation_enabled = true;

COMMIT;
```

All four steps are in a single transaction. If any step fails, the
version pointer is not updated and the lesson remains on the old
version.

## Rollback

Content version rollback means: point `lessons.content_version_id`
back to a previous version. This is a valid operation when a content
publish is discovered to be incorrect.

Rollback procedure:

1. Operator identifies the target rollback version UUID.
2. Operator runs `make content-rollback LESSON_ID=<uuid> VERSION_ID=<uuid>`.
3. The rollback script:
   a. Verifies the target version exists and predates the current version.
   b. Inserts a `content_version_events` row with `change_summary:
      "rollback to {version}"`.
   c. Updates `lessons.content_version_id` to the target version.
   d. Does NOT set `require_recompletion` — learners mid-lesson are
      not disrupted. Completions recorded during the bad version
      reference the bad version by ID; this is visible in the audit
      log and can be flagged for review.
4. The `LISTEN/NOTIFY` signal is emitted to invalidate caches.

A rollback does not delete the bad version. The bad version row
remains in `content_versions` for audit purposes. If completions were
recorded against the bad version, those completions are visible in
the evidence export and labelled with the bad version's hash —
allowing a reviewer to identify which learners completed the
erroneous content.

## Content diff strategy

The platform does not store content diffs. The source of truth for
what changed between two versions is the `content/` directory in the
git repository — git provides the diff natively. The
`content_versions.content_hash` field enables a verifier to
reconstruct and re-hash any historical version from the git history
and confirm it matches the stored hash.

For operational convenience (instructor dashboard), a diff summary is
rendered on demand by the API:

```
GET /api/v1/admin/content/versions/{version_id}/diff?against={old_version_id}
Authorization: Bearer <admin-token>

200 OK
{
  "lesson_id":     "uuid",
  "new_version":   "1.2.0",
  "old_version":   "1.1.0",
  "change_summary": "Added two new scenario questions; updated CVE references.",
  "hash_old":      "blake3:...",
  "hash_new":      "blake3:..."
}
```

The `change_summary` is the human-readable string provided by the
content author at publish time. The API does not compute a syntactic
diff of the markdown — that is git's job.

## API contract

### Get current version for a lesson

```
GET /api/v1/lessons/{lesson_id}/version
Authorization: Bearer <token>

200 OK
{
  "lesson_id":          "uuid",
  "content_version_id": "uuid",
  "revision":           "1.2.0",
  "content_hash":       "blake3:...",
  "published_at":       "2025-05-06T08:00:00Z"
}
```

### List version history for a lesson

```
GET /api/v1/admin/content/lessons/{lesson_id}/versions
Authorization: Bearer <admin-token>

200 OK
{
  "lesson_id": "uuid",
  "versions": [
    {
      "content_version_id":   "uuid",
      "revision":             "1.2.0",
      "content_hash":         "blake3:...",
      "require_recompletion": false,
      "change_summary":       "Typo fix in measure (b) description",
      "published_at":         "2025-05-06T08:00:00Z"
    },
    {
      "content_version_id":   "uuid",
      "revision":             "1.1.0",
      "content_hash":         "blake3:...",
      "require_recompletion": true,
      "change_summary":       "Quiz answers corrected for Q3",
      "published_at":         "2025-04-01T12:00:00Z"
    }
  ]
}
```

### Get version change events for a track

```
GET /api/v1/admin/content/paths/{path_slug}/events
Authorization: Bearer <admin-token>

200 OK
{
  "path_slug": "nis2-awareness",
  "events": [
    {
      "event_id":             "uuid",
      "lesson_id":            "uuid",
      "old_revision":         "1.1.0",
      "new_revision":         "1.2.0",
      "require_recompletion": false,
      "active_enrolments":    14,
      "event_at":             "2025-05-06T08:00:00Z",
      "published_by":         "uuid"
    }
  ]
}
```

### Trigger rollback (operator-only)

```
POST /api/v1/admin/content/lessons/{lesson_id}/rollback
Authorization: Bearer <operator-token>
Content-Type: application/json

{
  "target_version_id": "uuid",
  "reason":            "Published version contained incorrect quiz answers"
}

200 OK
{
  "lesson_id":          "uuid",
  "rolled_back_to":     "1.1.0",
  "previous_version":   "1.2.0",
  "event_id":           "uuid"
}
```

## `content_version_mismatch` error

If a learner's `progress` row was opened against a lesson on version
`A`, and version `B` is now published, and `B` sets
`require_recompletion: true`, the API returns
`content_version_mismatch` on the next `mark_complete` call:

```json
{
  "error":            "content_version_mismatch",
  "lesson_id":        "uuid",
  "your_version":     "1.1.0",
  "current_version":  "2.0.0",
  "action_required":  "restart_lesson"
}
```

This error is the circuit breaker that prevents a stale-content
completion from entering the audit record.

## Configuration

```bash
CYBERPATH_CONTENT_NOTIFY_CHANNEL=content_version_published
  # PostgreSQL LISTEN/NOTIFY channel name for cache invalidation
CYBERPATH_CERT_RECOMPLETION_INVALIDATES_CERT=false
  # If true, major-version lesson changes mark related certs as requires_renewal
CYBERPATH_CONTENT_PUBLISHER_ROLE=content_publisher
  # Database role used by the CI publisher job
```

## Error codes reference

| Code | HTTP status | Meaning |
|---|---|---|
| `version_not_found` | 404 | Content version UUID does not exist |
| `rollback_target_invalid` | 422 | Target version does not predate current version |
| `content_version_mismatch` | 409 | Lesson content changed; restart required before completing |
| `publish_hash_mismatch` | 422 | Computed content hash does not match source files |

## Observability

- `cyberpath_content_publishes_total` — counter, labels: `require_recompletion`, `bump_type` (`patch`|`minor`|`major`)
- `cyberpath_content_rollbacks_total` — counter
- `cyberpath_content_active_enrolment_migrations_total` — counter, labels: `action` (`notify`|`require_restart`)
- `cyberpath_content_version_cache_invalidations_total` — counter

## See also

- [module-1-learning-path.md](module-1-learning-path.md) — content version gating on lesson start/complete
- [module-5-certification.md](module-5-certification.md) — cert requires_renewal flow
- [architecture.md](architecture.md) — `content_versions` schema overview and audit invariant
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
