-- CyberPath migration 0003: assessments and labs.
--
-- Adds four tables on top of the v0.0.1 + 0002 core:
--   * quizzes          — quiz definitions, attached to a lesson and/or track.
--   * quiz_questions   — children of quizzes; multilingual prompt + choices.
--   * lab_definitions  — lab catalogue, transcribed from lab.yaml.
--   * lab_sessions     — runtime instances of a lab, partitioned by year.
--
-- Per docs/data-model.md, lab_sessions is partitioned by RANGE on
-- started_at for cold-storage efficiency. This migration creates the
-- parent table plus the 2026 partition; tooling for automated
-- partition management (rolling-create, archive, attach) lives in
-- v1.0.0.
--
-- Idempotent: every object uses IF NOT EXISTS guards so the migration
-- can be replayed safely against an already-migrated DB.

BEGIN;

-- ── Quizzes ───────────────────────────────────────────────────────
-- A quiz is attached to a lesson (per-lesson knowledge check) and/or
-- a track (standalone end-of-track quiz). At least one of the two FKs
-- must be set; the CHECK below enforces this.
CREATE TABLE IF NOT EXISTS quizzes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lesson_id           UUID REFERENCES lessons(id) ON DELETE CASCADE,
    track_id            UUID REFERENCES tracks(id) ON DELETE CASCADE,
    title_sq            TEXT NOT NULL DEFAULT '',
    title_en            TEXT NOT NULL DEFAULT '',
    -- pass_threshold is an integer percentage 0–100 (e.g. 80 = 80%).
    pass_threshold      INT  NOT NULL DEFAULT 80
        CHECK (pass_threshold BETWEEN 0 AND 100),
    time_limit_seconds  INT,
    version             INT  NOT NULL DEFAULT 1,
    -- content_hash: sha256 hex of the canonicalised quiz body, 64 chars.
    content_hash        VARCHAR(64) NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- At least one of lesson_id / track_id must be NOT NULL so the
    -- quiz is anchored somewhere in the curriculum.
    CONSTRAINT quizzes_anchor_chk
        CHECK (lesson_id IS NOT NULL OR track_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_quizzes_lesson ON quizzes(lesson_id);
CREATE INDEX IF NOT EXISTS idx_quizzes_track  ON quizzes(track_id);

-- ── Quiz questions ────────────────────────────────────────────────
-- Children of a quiz; ordered by `position` within the quiz. `kind`
-- mirrors the quiz YAML schema (see docs/track-content-guide.md).
CREATE TABLE IF NOT EXISTS quiz_questions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    quiz_id         UUID NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
    position        INT  NOT NULL,
    -- kind matches the question types in track-content-guide.md.
    kind            VARCHAR(32) NOT NULL
        CHECK (kind IN ('multiple_choice','true_false','code_fill','scenario')),
    prompt_sq       TEXT NOT NULL DEFAULT '',
    prompt_en       TEXT NOT NULL DEFAULT '',
    -- choices: JSONB array of {id, text_sq, text_en} for multiple_choice
    -- and scenario; NULL for code_fill / true_false.
    choices         JSONB,
    -- correct: JSONB array of choice ids (MC/scenario), boolean
    -- (true_false), or accepted patterns/strings (code_fill).
    correct         JSONB NOT NULL,
    explanation_sq  TEXT,
    explanation_en  TEXT,
    points          INT  NOT NULL DEFAULT 1,
    UNIQUE (quiz_id, position)
);
CREATE INDEX IF NOT EXISTS idx_quiz_questions_quiz ON quiz_questions(quiz_id);

-- ── Lab definitions ───────────────────────────────────────────────
-- Transcribed from labs/<slug>/lab.yaml (see docs/lab-content-guide.md).
-- The `id` is the slug (e.g. `phishing/recognise-spear`) so that
-- content references stay stable across re-imports.
CREATE TABLE IF NOT EXISTS lab_definitions (
    id                  VARCHAR(128) PRIMARY KEY,
    track_id            UUID REFERENCES tracks(id) ON DELETE RESTRICT,  -- nullable: cross-track labs
    -- runtime: 'docker' is v1.0.0-only (Module 3 bridge runtime);
    -- 'wasmtime' is the v1.0.0+ default (see docs/wasm-sandbox.md).
    runtime             VARCHAR(16) NOT NULL
        CHECK (runtime IN ('docker','wasmtime')),
    image               VARCHAR(256) NOT NULL DEFAULT '',
    entry_command       TEXT NOT NULL DEFAULT '',
    assets              JSONB NOT NULL DEFAULT '[]'::jsonb,
    validation          JSONB NOT NULL DEFAULT '[]'::jsonb,
    time_limit_seconds  INT  NOT NULL DEFAULT 1800,
    egress_whitelist    JSONB NOT NULL DEFAULT '[]'::jsonb,
    success_criteria    TEXT NOT NULL DEFAULT '',
    hints               JSONB NOT NULL DEFAULT '[]'::jsonb,
    version             INT  NOT NULL DEFAULT 1,
    -- content_hash: sha256 hex of the canonicalised lab body, 64 chars.
    content_hash        VARCHAR(64) NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_lab_definitions_track ON lab_definitions(track_id);

-- ── Lab sessions (partitioned by year on started_at) ──────────────
-- Per data-model.md, lab_sessions grows unboundedly and is
-- partitioned by RANGE(started_at) for cold-storage efficiency.
-- Postgres requires the partition key to be part of the PK, hence
-- the composite (id, started_at) primary key. Tooling for partition
-- management (rolling-create, archive, attach) lives in v1.0.0.
CREATE TABLE IF NOT EXISTS lab_sessions (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    lab_id          VARCHAR(128) NOT NULL REFERENCES lab_definitions(id) ON DELETE RESTRICT,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    cohort_id       UUID REFERENCES cohorts(id) ON DELETE SET NULL,  -- nullable: only set for cohort-launched sessions
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,  -- denormalised for tenant isolation
    -- status: lifecycle of the session; runtime transitions are
    -- enforced at the application layer.
    status          VARCHAR(16) NOT NULL
        CHECK (status IN ('starting','running','completed','failed','timeout','cancelled')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    -- runtime is copied from lab_definitions at session start time
    -- and is immutable thereafter (so historical sessions remain
    -- replayable even if the lab definition is bumped to a new runtime).
    runtime         VARCHAR(16) NOT NULL
        CHECK (runtime IN ('docker','wasmtime')),
    result          JSONB NOT NULL DEFAULT '{}'::jsonb,
    audit_log_url   TEXT NOT NULL DEFAULT '',
    -- audit_hash: sha256 hex of the audit log object, 64 chars.
    audit_hash      VARCHAR(64) NOT NULL DEFAULT '',
    outcome_score   INT
        CHECK (outcome_score IS NULL OR (outcome_score BETWEEN 0 AND 100)),
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, started_at)
) PARTITION BY RANGE (started_at);

CREATE INDEX IF NOT EXISTS idx_lab_sessions_user        ON lab_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_lab         ON lab_sessions(lab_id);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_tenant      ON lab_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_status      ON lab_sessions(status);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_started_at  ON lab_sessions(started_at);
-- Composite for "my recent labs" queries.
CREATE INDEX IF NOT EXISTS idx_lab_sessions_user_started
    ON lab_sessions(user_id, started_at DESC);

-- 2026 partition. Additional partitions are created by the
-- partition-management tooling that ships in v1.0.0.
CREATE TABLE IF NOT EXISTS lab_sessions_2026
    PARTITION OF lab_sessions
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

COMMIT;
