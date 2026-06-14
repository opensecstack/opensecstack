# Module 1: Learning Path Engine

> Status: scaffold. Implementation lives in `internal/path/` and the
> React learner UI lives in `web/src/learner/`. This document covers
> design intent for v1.0.0. Concrete code references land as the
> directories populate.

## Overview

The Learning Path Engine is the structural backbone of CyberPath. It
organises content into tracks, enforces prerequisite gating, advances
learners through lessons, awards XP, and emits completion records that
flow downstream to Module 5 (Certification Issuance) and Module 6
(CITADEL Evidence Emitter).

Every other module — quiz, lab, cert — is called by a learner who is
in a session managed by Module 1. Module 1 is the entry point.

## Track structure

A track (referred to as a "path" in the database and API) is the
top-level learning object. Each track contains one or more modules;
each module contains one or more lessons. The hierarchy is:

```
path (track)
 └── module (logical grouping)
      └── lesson (atomic content unit)
           ├── quiz (optional, Module 2)
           └── lab  (optional, Module 3 or 4)
```

Content is authored under `content/<track-slug>/` and shipped
alongside the compiled binary at build time. The filesystem layout
matches the DB structure:

```
content/nis2-awareness/
  track.yaml
  lessons/
    01-scope.sq.md
    01-scope.en.md
    02-measures.sq.md
    02-measures.en.md
  quizzes/
    01-scope.yaml
    02-measures.yaml
```

`track.yaml` is the authoritative metadata file. Required fields:

```yaml
id: nis2-awareness
slug: nis2-awareness
title_sq: "Ndërgjegjësimi mbi NIS2 Neni 21"
title_en: "NIS2 Article 21 Awareness"
audience: all-staff
nis2_measure: "21(2)(g)"
cert_offered: true
prerequisites: []
estimated_hours: 1.5
version: "1.0.0"
```

## Prerequisite gating

A track may declare one or more prerequisite track slugs. The engine
enforces this gate at enrolment time: a learner who has not completed
every prerequisite track cannot start the dependent track.

Completion means: all lessons in the prerequisite track have a row in
`completions` for the learner, and every quiz/lab in those lessons has
a passing score.

Prerequisite resolution is a DAG traversal. The engine detects cycles
at track-load time (startup) and refuses to start if any cycle is
found. Circular prerequisites are a content error, not a runtime one.

```go
// internal/path/prereq.go (design intent)
func ResolvePrereqs(slug string, registry TrackRegistry) ([]string, error)
// Returns the ordered list of slugs that must be completed before slug.
// Returns ErrCyclicPrereq if the graph has a cycle.
```

The resolution result is cached per process lifetime; track content
changes trigger a cache bust via Module 8 signals.

## Progression logic

Lessons within a track are ordered (the `order` column on the
`lessons` table). A learner progresses sequentially; lesson N+1 is
gated behind lesson N being completed.

The gate is evaluated server-side on every `POST
/api/v1/lessons/{lesson_id}/start`. Returning `403 Forbidden` with a
`prerequisite_lesson_not_complete` error code is the standard response
when the gate is not met. The frontend uses this to render the lesson
as locked.

A lesson is considered **started** when the learner calls `start` and
a `progress` row is upserted. A lesson is considered **complete** when
`mark_complete` is called after all required sub-items (quiz passes,
lab pass) are satisfied.

### Sub-item requirements

| Lesson has | Required to complete lesson |
|---|---|
| No quiz, no lab | Mark-complete call alone |
| Quiz only | Passing quiz attempt |
| Lab only | Passing lab validation |
| Quiz and lab | Passing quiz attempt + passing lab validation |

The engine checks sub-item state before accepting `mark_complete`.
Clients cannot skip this check — it is enforced at the API layer, not
in the frontend.

## XP and scoring

Every lesson carries a base XP value. Bonus XP is awarded for:

- First attempt pass on a quiz (no retries used): +20% of base
- Lab completed under the first session time budget: +10% of base
- Track completed before the soft deadline (if the org admin set one): +50 flat XP

XP is advisory — it powers leaderboards and the learner dashboard —
and does not block completion. The `completions` table records the
raw score; a separate materialised view `learner_xp_totals` is
refreshed on each completion insert by a PostgreSQL trigger.

XP values are set in `track.yaml` per lesson:

```yaml
lessons:
  - id: scope
    order: 1
    xp: 100
    has_quiz: true
    has_lab: false
```

## Database schema

### `paths`

```sql
CREATE TABLE paths (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,
    title_sq        TEXT NOT NULL,
    title_en        TEXT NOT NULL,
    audience        TEXT NOT NULL,
    nis2_measure    TEXT,
    cert_offered    BOOLEAN NOT NULL DEFAULT false,
    prerequisites   TEXT[] NOT NULL DEFAULT '{}',
    estimated_hours NUMERIC(5, 1),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### `modules`

```sql
CREATE TABLE modules (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    path_id  UUID NOT NULL REFERENCES paths(id) ON DELETE CASCADE,
    "order"  INTEGER NOT NULL,
    title_sq TEXT NOT NULL,
    title_en TEXT NOT NULL,
    UNIQUE (path_id, "order")
);
```

### `lessons`

```sql
CREATE TABLE lessons (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id          UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    "order"            INTEGER NOT NULL,
    content_version_id UUID NOT NULL REFERENCES content_versions(id),
    has_quiz           BOOLEAN NOT NULL DEFAULT false,
    has_lab            BOOLEAN NOT NULL DEFAULT false,
    xp_base            INTEGER NOT NULL DEFAULT 100,
    UNIQUE (module_id, "order")
);
```

### `progress`

```sql
CREATE TABLE progress (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id    UUID NOT NULL REFERENCES lessons(id),
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, lesson_id)
);
```

### `completions`

```sql
CREATE TABLE completions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id          UUID NOT NULL REFERENCES lessons(id),
    content_version_id UUID NOT NULL REFERENCES content_versions(id),
    score              NUMERIC(5, 2),
    xp_awarded         INTEGER NOT NULL DEFAULT 0,
    completed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    evidence_hash      TEXT NOT NULL,
    UNIQUE (user_id, lesson_id)
);
```

`completions` is the immutable record of achievement. Rows are never
updated or deleted. If a learner retakes a track (post-content-change,
per Module 8 rules), a new completion row is inserted; the old one is
retained for audit history.

## API contract

All endpoints require a valid session token (Bearer, via
opensecstack/sdk auth middleware).

### Enrol in a track

```
POST /api/v1/paths/{path_slug}/enrol
Authorization: Bearer <token>

200 OK
{
  "path_id": "uuid",
  "slug":    "nis2-awareness",
  "status":  "enrolled",
  "first_lesson_id": "uuid"
}

403 Forbidden — prerequisite_not_met
{
  "error": "prerequisite_not_met",
  "missing": ["track-slug-1"]
}
```

### Start a lesson

```
POST /api/v1/lessons/{lesson_id}/start
Authorization: Bearer <token>

200 OK
{
  "lesson_id":          "uuid",
  "content_version_id": "uuid",
  "content_url":        "/api/v1/lessons/{lesson_id}/content",
  "has_quiz":           true,
  "has_lab":            false,
  "xp_base":            100
}

403 Forbidden — lesson_gated
{
  "error": "lesson_gated",
  "requires_lesson_id": "uuid"
}
```

### Mark a lesson complete

```
POST /api/v1/lessons/{lesson_id}/complete
Authorization: Bearer <token>

200 OK
{
  "completion_id": "uuid",
  "xp_awarded":    120,
  "track_complete": false
}

409 Conflict — sub_items_incomplete
{
  "error":   "sub_items_incomplete",
  "pending": ["quiz"]
}
```

### Get learner progress for a track

```
GET /api/v1/paths/{path_slug}/progress
Authorization: Bearer <token>

200 OK
{
  "path_id":             "uuid",
  "slug":                "nis2-awareness",
  "percent_complete":    40,
  "lessons_complete":    2,
  "lessons_total":       5,
  "xp_earned":           220,
  "next_lesson_id":      "uuid"
}
```

## Configuration

Module 1 reads configuration from environment variables (viper, env
overrides YAML):

```bash
CYBERPATH_PATH_XP_BONUS_FIRST_ATTEMPT=0.20  # 20% bonus for first-attempt quiz pass
CYBERPATH_PATH_XP_BONUS_LAB_FAST=0.10       # 10% bonus for lab under-budget completion
CYBERPATH_PATH_XP_BONUS_DEADLINE_FLAT=50    # flat XP bonus for on-time track completion
CYBERPATH_PATH_PREREQ_CACHE_TTL=3600        # seconds; 0 = disabled (resolve every time)
```

Content-change signals from Module 8 invalidate the prerequisite
resolution cache immediately regardless of TTL.

## Error codes reference

| Code | HTTP status | Meaning |
|---|---|---|
| `prerequisite_not_met` | 403 | Learner has not completed required track(s) |
| `lesson_gated` | 403 | Previous lesson in sequence not completed |
| `lesson_not_found` | 404 | Lesson UUID does not exist |
| `sub_items_incomplete` | 409 | Quiz or lab not yet passed for this lesson |
| `already_enrolled` | 409 | Duplicate enrolment attempt |
| `content_version_mismatch` | 409 | Lesson content changed mid-session (Module 8 signal) |

## Observability

- `cyberpath_lesson_starts_total` — counter, labels: `path_slug`, `lesson_order`
- `cyberpath_lesson_completions_total` — counter, labels: `path_slug`, `lesson_order`
- `cyberpath_track_completions_total` — counter, labels: `path_slug`
- `cyberpath_prerequisite_gate_rejects_total` — counter, labels: `path_slug`

All on the `/metrics` endpoint, unauthenticated, same as ecosystem
convention.

## See also

- [architecture.md](architecture.md) — system topology and DB schema overview
- [module-2-quiz.md](module-2-quiz.md) — quiz sub-items
- [module-3-docker-labs.md](module-3-docker-labs.md) — lab sub-items (Docker)
- [module-4-wasm-labs.md](module-4-wasm-labs.md) — lab sub-items (Wasm)
- [module-5-certification.md](module-5-certification.md) — track completion → certificate
- [module-8-content-versioning.md](module-8-content-versioning.md) — version signals
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
