-- CyberPath migration 0002: cohorts, roles, and cohort enrolments.
--
-- Adds three tables to the v0.0.1 core:
--   * roles               — RBAC role catalogue (seeded with 4 defaults).
--   * cohorts             — instructor-managed learner groups.
--   * cohort_enrollments  — N:M link between users and cohorts.
--
-- Also extends `users` with a `role_id` FK referencing `roles(id)`,
-- defaulting to 'learner', and backfills existing rows so the column
-- is NOT NULL after this migration runs.
--
-- Idempotent: every object uses IF NOT EXISTS / ON CONFLICT guards so
-- the migration can be replayed safely against an already-migrated DB.

BEGIN;

-- ── Roles (RBAC role catalogue) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS roles (
    id          VARCHAR(32) PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed default roles. ON CONFLICT keeps replays no-op.
INSERT INTO roles (id, description, permissions) VALUES
    ('admin',      'Platform administrator — full tenant control.',                 '["*"]'::jsonb),
    ('instructor', 'Cohort owner — authors content, manages learners, attests.',    '["cohort.*","track.author","completion.override","cert.revoke"]'::jsonb),
    ('learner',    'End user — consumes tracks, submits quizzes, runs labs.',       '["lesson.read","quiz.attempt","lab.run","progress.self"]'::jsonb),
    ('auditor',    'Read-only auditor — coverage queries, evidence export.',        '["audit.read","completion.read","cert.read","coverage.read"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ── Users.role_id (RBAC linkage) ──────────────────────────────────
-- Add the FK column nullable, backfill, then enforce NOT NULL. The
-- DO block keeps the ALTER idempotent across replays.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role_id VARCHAR(32)
        REFERENCES roles(id) ON DELETE RESTRICT;

UPDATE users SET role_id = 'learner' WHERE role_id IS NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users'
          AND column_name = 'role_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE users
            ALTER COLUMN role_id SET DEFAULT 'learner',
            ALTER COLUMN role_id SET NOT NULL;
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);

-- ── Cohorts (instructor-managed learner groups) ───────────────────
CREATE TABLE IF NOT EXISTS cohorts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    track_id    UUID REFERENCES tracks(id) ON DELETE RESTRICT,  -- nullable: multi-track cohorts
    start_date  DATE,
    end_date    DATE,
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status      TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned','active','completed','archived')),
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cohorts_tenant     ON cohorts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cohorts_track      ON cohorts(track_id);
CREATE INDEX IF NOT EXISTS idx_cohorts_status     ON cohorts(status);
CREATE INDEX IF NOT EXISTS idx_cohorts_created_by ON cohorts(created_by);

-- ── Cohort enrolments (N:M users ↔ cohorts) ───────────────────────
CREATE TABLE IF NOT EXISTS cohort_enrollments (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cohort_id         UUID NOT NULL REFERENCES cohorts(id) ON DELETE CASCADE,
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    enrolled_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    enrolled_by       UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    unenrolled_at     TIMESTAMPTZ,
    completion_status TEXT NOT NULL DEFAULT 'planned'
        CHECK (completion_status IN ('planned','in_progress','completed','dropped'))
);
CREATE INDEX IF NOT EXISTS idx_cohort_enrollments_user   ON cohort_enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_cohort_enrollments_cohort ON cohort_enrollments(cohort_id);

-- One active enrolment per (cohort, user); historical rows with
-- `unenrolled_at` set are excluded so a learner can be re-enrolled.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cohort_enrollments_active
    ON cohort_enrollments(cohort_id, user_id)
    WHERE unenrolled_at IS NULL;

COMMIT;
