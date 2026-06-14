# CyberPath Data Model

> Status: scaffold for v1.0.0 → v1.0.0. Concrete migrations land
> under `internal/db/migrations/` as the schema solidifies. The
> shape below is the design intent; field names confirmed at
> v0.0.1 implementation may differ in case/spelling but not in
> structure.

## Database: PostgreSQL 16

CyberPath persists every learner identity, content snapshot, lesson
completion, lab session, and audit event in a dedicated `cyberpath`
PostgreSQL database. The schema is **audit-by-design**: completion
records are append-only, content snapshots are immutable, and every
completion references the exact `content_version_id` of the lesson
the learner saw so an auditor can independently reproduce the body
of evidence.

For migration tooling and procedures, see
[migrations.md](migrations.md). For the CITADEL evidence contract,
see [citadel-integration.md](citadel-integration.md).

---

## Entity-relationship overview

```
                         ┌──────────────┐
                         │   tenants    │
                         └──────┬───────┘
                                │ 1:N
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
        ┌──────────┐      ┌──────────┐     ┌──────────────┐
        │  users   │◄─────┤  roles   │     │   cohorts    │
        └────┬─────┘  N:M └──────────┘     └──────┬───────┘
             │                                     │ 1:N
             │ 1:N                                 ▼
             │                            ┌────────────────────┐
             │                            │ cohort_enrollments │
             │                            └─────────┬──────────┘
             │                                      │ N:1
             ▼                                      ▼
      ┌──────────────┐                       ┌──────────┐
      │   progress   │──────────────────────►│  users   │
      └──────┬───────┘                       └──────────┘
             │
             │
             ▼
      ┌──────────────┐    1:N   ┌──────────┐   1:N   ┌──────────┐
      │   tracks     │─────────►│ modules  │────────►│ lessons  │
      └──────┬───────┘          └──────────┘         └────┬─────┘
             │                                            │
             │                                            │ 1:N
             │ 1:N                                        ▼
             ▼                                      ┌──────────┐
      ┌──────────────────┐                          │ quizzes  │
      │ certifications   │◄──────┐                  └────┬─────┘
      └──────────────────┘       │ 1:N                   │ 1:N
                                 │                       ▼
      ┌──────────────────┐       │                ┌────────────────┐
      │   completions    │───────┘                │ quiz_questions │
      └────────┬─────────┘                        └────────────────┘
               │ N:1
               ▼
      ┌──────────────────┐
      │ content_versions │       ┌──────────────────┐
      └──────────────────┘       │ lab_definitions  │
                                 └────────┬─────────┘
                                          │ 1:N
                                          ▼
                                 ┌──────────────────┐
                                 │  lab_sessions    │
                                 └──────────────────┘

      ┌──────────────────┐  ┌──────────────────┐  ┌──────────┐
      │  audit_events    │  │     webhooks     │  │ outbox   │
      └──────────────────┘  └──────────────────┘  └──────────┘
                                                    (CITADEL)
```

The audit chain is `completions → content_versions` (immutable) and
`completions → outbox → CITADEL WORM`.

---

## Tables

### `tenants`

Multi-tenant boundary. v1.0.0 ships with a single default tenant;
v1.0.0+ exposes per-deployment multi-tenant policies (row-level
isolation in v1.0.0, per-schema in v1.1+).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `slug` | TEXT UNIQUE | URL-safe identifier |
| `display_name` | TEXT | Human-readable name |
| `created_at` | TIMESTAMPTZ | |
| `deleted_at` | TIMESTAMPTZ NULL | Soft-delete marker (GDPR tenant-level erase, deferred to v1.1+) |

**Indexes**: `(slug)` UNIQUE, partial `(deleted_at) WHERE deleted_at IS NULL`.
**Retention**: indefinite. **GDPR**: non-PII (organisational metadata).

### `roles`

Role catalogue. Bound to users via `user_roles` (link table, omitted
from the ERD above for clarity).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `slug` | TEXT UNIQUE | `learner`, `instructor`, `admin`, `auditor` |
| `display_name` | TEXT | |
| `permissions` | JSONB | Permission strings; resolved by SDK middleware |

**Retention**: indefinite. **GDPR**: non-PII.

### `users`

Learner identity. Argon2id password hash via `opensecstack/sdk`.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `tenant_id` | UUID | FK `tenants(id)` ON DELETE RESTRICT |
| `email` | TEXT | UNIQUE per tenant; PII |
| `display_name` | TEXT | PII |
| `argon2_hash` | TEXT | password hash |
| `locale` | TEXT | `sq` / `en`; default `sq` |
| `created_at` | TIMESTAMPTZ | |
| `last_seen_at` | TIMESTAMPTZ NULL | |
| `deleted_at` | TIMESTAMPTZ NULL | Soft-delete |

**Indexes**: UNIQUE `(tenant_id, lower(email))`, `(last_seen_at DESC)`.
**FKs**: `tenant_id → tenants(id)` ON DELETE RESTRICT.
**Retention**: while tenant exists; soft-deleted users are retained
indefinitely so historical completions remain valid evidence.
**GDPR**: PII (`email`, `display_name`). Right-to-erase at the
*tenant* level is deferred to v1.1+ per ADR-012; per-user erase is
not supported because completion records are audit evidence (the
user identifier is hashed via the evidence chain, but the
`users` row itself is retained).

### `tracks`

A learning path (ecosystem term: "track"; ADR uses `paths` and
`tracks` interchangeably — the schema canonicalises on `tracks`).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `slug` | TEXT UNIQUE | e.g. `phishing-recognition` |
| `title_sq` | TEXT | Albanian title |
| `title_en` | TEXT | English title |
| `audience` | TEXT | `all-staff`, `engineering`, `soc`, `sysadmin` |
| `nis2_measures` | TEXT[] | e.g. `{art21.g, art21.b}` |
| `cert_offered` | BOOLEAN | |
| `cert_default_validity_days` | INT | e.g. 365 for phishing, 730 for secure-coding |
| `version` | TEXT | semver, e.g. `1.4.0` |
| `created_at` | TIMESTAMPTZ | |

**Indexes**: GIN on `nis2_measures`, `(audience)`, `(slug)` UNIQUE.
**Retention**: indefinite. **GDPR**: non-PII.

### `modules`

Logical grouping inside a track.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `track_id` | UUID | FK `tracks(id)` ON DELETE RESTRICT |
| `ord` | INT | Position within the track |
| `title_sq` / `title_en` | TEXT | |

**Indexes**: `(track_id, ord)` UNIQUE.

### `lessons`

Atomic content unit. The lesson body itself lives in
`content_versions`; the `lessons` row is the *identity* — the body
changes via new revisions, not by mutating the body in place.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `module_id` | UUID | FK `modules(id)` ON DELETE RESTRICT |
| `ord` | INT | |
| `slug` | TEXT | URL slug, unique within module |
| `current_content_version_id` | UUID | FK `content_versions(id)`; the version served to new starts |
| `has_lab` | BOOLEAN | |
| `has_quiz` | BOOLEAN | |
| `created_at` | TIMESTAMPTZ | |

**Indexes**: `(module_id, ord)` UNIQUE, `(slug)`.

### `content_versions`

Immutable lesson snapshots. Module 8 ("Content Versioning") enforces
append-only — once written, rows are never UPDATEd or DELETEd.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `lesson_id` | UUID | FK `lessons(id)` ON DELETE RESTRICT |
| `revision` | INT | 1, 2, 3, … per lesson |
| `body_sq` | TEXT | Albanian markdown source |
| `body_en` | TEXT | English markdown source |
| `content_hash` | TEXT | BLAKE3 of canonicalised body (`blake3:<hex>`) |
| `created_at` | TIMESTAMPTZ | |
| `created_by` | UUID NULL | FK `users(id)` of the authoring instructor |

**Indexes**: `(lesson_id, revision)` UNIQUE, `(content_hash)`.
**Retention**: indefinite — completions reference these by id, so
removing a version would break audit reproducibility.
**GDPR**: non-PII (lesson content).

### `quizzes`

Quiz definitions attached to a lesson.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `lesson_id` | UUID | FK `lessons(id)` ON DELETE RESTRICT |
| `bank_ref` | TEXT | Reference to a question-bank id |
| `randomise` | BOOLEAN | |
| `pass_threshold` | NUMERIC(4,3) | e.g. 0.700 |

### `quiz_questions`

Question bank. Multilingual question + choices; correct-answer index
stored separately from the rendered choices to keep auditing simple.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `quiz_id` | UUID | FK `quizzes(id)` ON DELETE CASCADE |
| `ord` | INT | |
| `prompt_sq` / `prompt_en` | TEXT | |
| `choices_sq` / `choices_en` | JSONB | `["a", "b", "c", "d"]` |
| `correct_indices` | INT[] | 0-based; multi-select supported |
| `explanation_sq` / `explanation_en` | TEXT NULL | |

**Indexes**: `(quiz_id, ord)` UNIQUE.

### `lab_definitions`

Lab catalogue. Each row is a lab the learner can launch from a
lesson. Lab images are pulled from the OCI registry (see
[wasm-sandbox.md](wasm-sandbox.md)).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `slug` | TEXT UNIQUE | e.g. `phish-classify-1` |
| `runtime` | TEXT | `docker` (v1.0.0) / `wasmtime` (v1.0.0+) |
| `image_ref` | TEXT | OCI ref, e.g. `ghcr.io/opensecstack/cyberpath-labs/phish-classify-1:1.4.0` |
| `image_digest` | TEXT | `sha256:<hex>` — pinned digest |
| `cosign_signature_ref` | TEXT NULL | Cosign signature reference (v1.0.0+) |
| `cpu_limit` | INT | cores |
| `memory_limit_mb` | INT | |
| `wallclock_limit_s` | INT | |
| `created_at` | TIMESTAMPTZ | |

### `lab_sessions`

Per-session lab telemetry. One row per launch.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `user_id` | UUID | FK `users(id)` ON DELETE RESTRICT |
| `lab_definition_id` | UUID | FK `lab_definitions(id)` ON DELETE RESTRICT |
| `started_at` | TIMESTAMPTZ | |
| `ended_at` | TIMESTAMPTZ NULL | |
| `exit_code` | INT NULL | |
| `resource_metrics` | JSONB | peak memory, cpu seconds, bytes in/out |
| `audit_log_ref` | TEXT NULL | object-store ref to the per-session command log |

**Indexes**: `(user_id, started_at DESC)`, `(lab_definition_id, started_at DESC)`.
**Retention**: 2 years hot, then archive. **GDPR**: PII (links to user).

### `cohorts`

Group of learners moving through tracks together (typical for
instructor-led training).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `tenant_id` | UUID | FK `tenants(id)` ON DELETE RESTRICT |
| `slug` | TEXT | unique within tenant |
| `display_name` | TEXT | |
| `track_id` | UUID | FK `tracks(id)` |
| `starts_at` / `ends_at` | TIMESTAMPTZ | |
| `created_at` | TIMESTAMPTZ | |

**Indexes**: `(tenant_id, slug)` UNIQUE, `(ends_at)`.

### `cohort_enrollments`

Link table — N:M between users and cohorts.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `cohort_id` | UUID | FK `cohorts(id)` ON DELETE CASCADE |
| `user_id` | UUID | FK `users(id)` ON DELETE RESTRICT |
| `enrolled_at` | TIMESTAMPTZ | |

**Indexes**: `(cohort_id, user_id)` UNIQUE.

### `progress`

In-flight learner state per lesson. Mutable — overwritten as the
learner advances. Distinct from `completions`, which are immutable.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `user_id` | UUID | FK `users(id)` ON DELETE RESTRICT |
| `lesson_id` | UUID | FK `lessons(id)` ON DELETE RESTRICT |
| `started_at` | TIMESTAMPTZ | |
| `last_seen_at` | TIMESTAMPTZ | |
| `state` | JSONB | scrubber position, partial quiz answers, lab session ref |

**Indexes**: `(user_id, lesson_id)` UNIQUE, `(last_seen_at DESC)`.
**Retention**: 90 days after last activity, then GC. **GDPR**: PII.

### `completions`

**Append-only.** One row per (user, lesson, content_version)
completion. The audit-grade table.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key (= `completion_id` in the CITADEL event) |
| `user_id` | UUID | FK `users(id)` ON DELETE RESTRICT |
| `lesson_id` | UUID | FK `lessons(id)` ON DELETE RESTRICT |
| `content_version_id` | UUID | FK `content_versions(id)` ON DELETE RESTRICT — the load-bearing audit field |
| `score` | NUMERIC(4,3) | 0.000–1.000; 1.000 for non-quiz |
| `evidence_hash` | TEXT | `blake3:<hex>` of the canonical evidence body |
| `signed_by` | TEXT | `ed25519:<key id>` |
| `citadel_ledger_id` | TEXT NULL | filled in once CITADEL acks (best-effort) |
| `completed_at` | TIMESTAMPTZ | |

**Indexes**: `(user_id, completed_at DESC)`, `(lesson_id, completed_at DESC)`,
`(content_version_id)`, `(citadel_ledger_id) WHERE citadel_ledger_id IS NULL`
(reconciliation sweep).
**Retention**: indefinite. **GDPR**: PII via FK to `users`. Schema
guarantees no DELETE; tenant-level erase (v1.1+) operates by
deleting the parent `tenants` row in a controlled procedure that
includes a CITADEL "erase manifest" event.

### `certifications`

Per-track signed completion certificates. Issued when a learner
completes every lesson + lab + quiz in a track.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `user_id` | UUID | FK `users(id)` ON DELETE RESTRICT |
| `track_id` | UUID | FK `tracks(id)` ON DELETE RESTRICT |
| `track_version` | TEXT | semver at issuance time |
| `issued_at` | TIMESTAMPTZ | |
| `expires_at` | TIMESTAMPTZ NULL | per-track default (see `tracks.cert_default_validity_days`) |
| `signature` | TEXT | Ed25519 over canonical certification body |
| `signing_key_id` | TEXT | e.g. `cyberpath-cert-2027a` |
| `revoked_at` | TIMESTAMPTZ NULL | governance-only field |
| `revoked_reason` | TEXT NULL | |

**Indexes**: `(user_id, track_id, issued_at DESC)`,
`(expires_at) WHERE revoked_at IS NULL`.
**Retention**: indefinite (audit evidence). **GDPR**: PII.

### `audit_events`

Append-only audit trail for every state-changing API call.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `actor` | TEXT | JWT `sub` |
| `role` | TEXT | role at request time |
| `action` | TEXT | `lesson.complete`, `cert.issue`, `lab.start`, … |
| `target_type` / `target_id` | TEXT | resource touched |
| `outcome` | TEXT | `success` / `denied` / `error` |
| `status_code` | INT | |
| `request_id` | TEXT | trace correlation |
| `remote_ip` | INET | PII |
| `metadata` | JSONB | structured context |
| `ts` | TIMESTAMPTZ | |

**Indexes**: `(ts DESC)`, `(actor, ts DESC)`, `(action, ts DESC)`.
**Retention**: 7 years (NIS2 audit window). **GDPR**: PII (`remote_ip`).

### `webhooks`

Outbound webhook subscribers (e.g. an external SIEM that wants
completion events mirrored).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `tenant_id` | UUID | FK `tenants(id)` ON DELETE CASCADE |
| `url` | TEXT | |
| `hmac_secret` | TEXT | encrypted at the application layer |
| `event_filters` | TEXT[] | e.g. `{lesson.completed, cert.issued}` |
| `active` | BOOLEAN | partial index `WHERE active = TRUE` |
| `created_at` | TIMESTAMPTZ | |

### `outbox`

CITADEL submission outbox — the local durable queue. Drained by
`internal/citadel/`. See [citadel-integration.md](citadel-integration.md).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `correlation_id` | UUID UNIQUE | dedup key, sent to CITADEL |
| `event_type` | TEXT | `cyberpath.completion`, `cyberpath.correction` |
| `payload` | JSONB | canonicalised event body |
| `attempts` | INT | retry counter |
| `next_attempt_at` | TIMESTAMPTZ | |
| `submitted_at` | TIMESTAMPTZ NULL | |
| `ledger_id` | TEXT NULL | filled on CITADEL ack |
| `created_at` | TIMESTAMPTZ | |

**Indexes**: `(submitted_at) WHERE submitted_at IS NULL`,
`(next_attempt_at) WHERE submitted_at IS NULL`.
**Retention**: 30 days after `submitted_at`, then GC. The
authoritative copy is in CITADEL.

---

## Hot vs cold partitioning

Two tables grow unboundedly: `completions` and `lab_sessions`. Both
are partitioned by `RANGE (completed_at)` / `RANGE (started_at)` per
year once daily volume crosses the threshold (target: ~5M rows per
table per year).

```sql
-- 0014_partition_completions.sql (illustrative; lands when volume crosses threshold)
ALTER TABLE completions
    PARTITION BY RANGE (completed_at);

CREATE TABLE completions_2027 PARTITION OF completions
    FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');

CREATE TABLE completions_2028 PARTITION OF completions
    FOR VALUES FROM ('2028-01-01') TO ('2029-01-01');
```

Cohort archival policy: cohorts whose `ends_at < now() - 5 years`
have their `lab_sessions` rows moved to a `lab_sessions_archive`
table on cold storage (cheaper class; `BRIN` index on
`started_at`). `completions` are *never* archived — they remain on
hot storage indefinitely, because they are the live audit surface.

---

## Soft-delete + GDPR right-to-erase

Soft-delete is supported on `users` and `tenants` via `deleted_at`.
Per-user GDPR erase is **not supported in v1.0.0** — completions are
audit evidence and cannot be selectively redacted without breaking
the chain to CITADEL.

Tenant-level erase (v1.1+ per ADR-012): orchestrated procedure that
(a) emits a `cyberpath.erasure` manifest event to CITADEL listing
the affected `completion_id`s, (b) overwrites PII columns
(`email`, `display_name`, `remote_ip`) on the affected rows with
the tombstone string `<erased>`, and (c) sets `tenants.deleted_at`.
The completion *fact* (a record of a completion happened) remains
audit-visible; the *identity* is severed.

---

## FK cascade rules

| FK | ON DELETE |
|---|---|
| `users.tenant_id → tenants.id` | RESTRICT |
| `cohorts.tenant_id → tenants.id` | RESTRICT |
| `cohort_enrollments.cohort_id → cohorts.id` | CASCADE |
| `cohort_enrollments.user_id → users.id` | RESTRICT |
| `modules.track_id → tracks.id` | RESTRICT |
| `lessons.module_id → modules.id` | RESTRICT |
| `quizzes.lesson_id → lessons.id` | RESTRICT |
| `quiz_questions.quiz_id → quizzes.id` | CASCADE |
| `content_versions.lesson_id → lessons.id` | RESTRICT |
| `progress.user_id → users.id` | RESTRICT |
| `progress.lesson_id → lessons.id` | RESTRICT |
| `completions.user_id → users.id` | RESTRICT |
| `completions.lesson_id → lessons.id` | RESTRICT |
| `completions.content_version_id → content_versions.id` | RESTRICT |
| `certifications.user_id → users.id` | RESTRICT |
| `certifications.track_id → tracks.id` | RESTRICT |
| `lab_sessions.user_id → users.id` | RESTRICT |
| `lab_sessions.lab_definition_id → lab_definitions.id` | RESTRICT |
| `webhooks.tenant_id → tenants.id` | CASCADE |

The pattern: anything that backs an audit trail is RESTRICT — the
parent cannot disappear while child evidence references it.
Anything that is purely ephemeral or per-tenant config is CASCADE.

---

## See also

- [migrations.md](migrations.md) — applying schema changes
- [architecture.md](architecture.md) — how each module reads/writes these tables
- [citadel-integration.md](citadel-integration.md) — outbox → WORM flow
- [nis2-integration.md](nis2-integration.md) — coverage queries derive from `completions`
- [wasm-sandbox.md](wasm-sandbox.md) — `lab_definitions` + `lab_sessions` semantics
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
