-- CyberPath v0.0.1 initial schema.
--
-- Minimal core: tenants, users, tracks, modules, lessons, progress,
-- completions, certifications. Apply with `make migrate-up`.
-- Use IF NOT EXISTS so this can be replayed safely against a clean DB.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Tenants (multi-tenant: one row per customer org) ──────────────
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Users ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'learner',
    locale      TEXT NOT NULL DEFAULT 'sq',
    password_hash TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);

-- ── Tracks ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tracks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    locale      TEXT NOT NULL DEFAULT 'en',
    difficulty  TEXT NOT NULL DEFAULT 'beginner',
    tags        TEXT[] NOT NULL DEFAULT '{}',
    nis2_refs   TEXT[] NOT NULL DEFAULT '{}',
    published   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tracks_locale ON tracks(locale);
CREATE INDEX IF NOT EXISTS idx_tracks_published ON tracks(published);

-- ── Modules (subdivisions of a track) ─────────────────────────────
CREATE TABLE IF NOT EXISTS modules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    track_id    UUID NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
    slug        TEXT NOT NULL,
    title       TEXT NOT NULL,
    ord         INT  NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (track_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_modules_track ON modules(track_id);

-- ── Lessons (atomic learning units inside a module) ───────────────
CREATE TABLE IF NOT EXISTS lessons (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id   UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    slug        TEXT NOT NULL,
    title       TEXT NOT NULL,
    locale      TEXT NOT NULL DEFAULT 'en',
    body_md     TEXT NOT NULL DEFAULT '',
    ord         INT  NOT NULL DEFAULT 0,
    duration_min INT NOT NULL DEFAULT 5,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (module_id, slug, locale)
);
CREATE INDEX IF NOT EXISTS idx_lessons_module ON lessons(module_id);

-- ── Progress (per-user, per-lesson tracking) ──────────────────────
CREATE TABLE IF NOT EXISTS progress (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id   UUID NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'in_progress',  -- in_progress | completed
    score       INT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE (user_id, lesson_id)
);
CREATE INDEX IF NOT EXISTS idx_progress_user ON progress(user_id);
CREATE INDEX IF NOT EXISTS idx_progress_lesson ON progress(lesson_id);

-- ── Completions (track-level / module-level milestones) ───────────
CREATE TABLE IF NOT EXISTS completions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,                        -- track | module | lesson
    target_id   UUID NOT NULL,
    score       INT,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    correlation_id TEXT,
    UNIQUE (user_id, kind, target_id)
);
CREATE INDEX IF NOT EXISTS idx_completions_user ON completions(user_id);
CREATE INDEX IF NOT EXISTS idx_completions_kind_target ON completions(kind, target_id);

-- ── Certifications (signed PDF + public verification URL) ─────────
CREATE TABLE IF NOT EXISTS certifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    track_id    UUID NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
    serial      TEXT NOT NULL UNIQUE,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    pdf_path    TEXT,
    signature   TEXT,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_certifications_user ON certifications(user_id);
CREATE INDEX IF NOT EXISTS idx_certifications_track ON certifications(track_id);

COMMIT;
