-- CyberPath migration 0007: cohort_tracks join table.
--
-- IRFlow's incoming webhook carries N track recommendations per
-- incident, but cohorts.track_id is a single column. Until now the
-- IRFlowCohortAdapter recorded the first trackID and dropped the rest
-- (see internal/wireup/adapters.go). This migration introduces a join
-- table so a cohort can be associated with 1..N tracks.
--
-- Schema choice
-- -------------
-- Some IRFlow recommendations arrive as track UUIDs (resolved via the
-- content registry); others arrive as slugs (e.g. "phishing-incident-
-- response") that have not yet been minted as DB rows. Both must be
-- representable. We therefore use a surrogate uuid PK with two
-- nullable reference columns:
--
--   * track_id   — uuid, nullable, FK to a tracks table when one
--                  exists. No FK constraint here yet because the
--                  tracks table itself is content-registry-managed
--                  and may not be present in every deployment.
--   * track_slug — text, nullable, opaque slug for unresolved refs.
--
-- A row MUST carry at least one (CHECK constraint). Uniqueness is
-- enforced per cohort via two partial unique indexes — one on
-- (cohort_id, track_id) WHERE track_id IS NOT NULL, the other on
-- (cohort_id, track_slug) WHERE track_slug IS NOT NULL. This avoids
-- the NULL-collation pitfalls that bite a composite UNIQUE on a
-- nullable column.
--
-- Lookup pattern: a cohort with multi-track recommendations leaves
-- cohorts.track_id NULL and gets one cohort_tracks row per track.
-- The legacy single-track shape (cohorts.track_id != NULL, no rows
-- in cohort_tracks) remains valid for older cohorts.
--
-- Idempotent. Apply with `make migrate-up`; safe to replay.

BEGIN;

CREATE TABLE IF NOT EXISTS cohort_tracks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cohort_id   UUID NOT NULL REFERENCES cohorts(id) ON DELETE CASCADE,
    track_id    UUID,
    track_slug  VARCHAR(128),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cohort_tracks_ref_present
        CHECK (track_id IS NOT NULL OR track_slug IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_cohort_tracks_cohort
    ON cohort_tracks (cohort_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cohort_tracks_cohort_track_id
    ON cohort_tracks (cohort_id, track_id)
    WHERE track_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cohort_tracks_cohort_track_slug
    ON cohort_tracks (cohort_id, track_slug)
    WHERE track_slug IS NOT NULL;

COMMIT;
