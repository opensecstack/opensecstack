-- CyberPath migration 0008: content_version_id on completions (Module 8).
--
-- Adds a nullable FK from completions → content_versions so that every
-- lesson/module/track completion record references the exact immutable
-- content snapshot the learner saw.  Nullable so existing rows and
-- deployments without content_versions populated are unaffected.
--
-- Idempotent: uses IF NOT EXISTS / IF NOT EXISTS guards.

BEGIN;

ALTER TABLE completions
    ADD COLUMN IF NOT EXISTS content_version_id UUID
        REFERENCES content_versions(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_completions_content_version
    ON completions(content_version_id);

COMMIT;
