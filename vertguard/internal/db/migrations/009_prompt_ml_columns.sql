-- VertGuard migration 009 — Module 3 (Prompt Injection) ML enrichment columns.
--
-- Adds columns to persist the ML enricher verdict alongside the regex
-- result. Previously these fields were computed by ScanWithML but never
-- written to prompt_scans, making post-hoc ML accuracy analysis
-- impossible.
--
-- Idempotent — safe to run against a fresh or already-migrated database.

ALTER TABLE prompt_scans
    ADD COLUMN IF NOT EXISTS ml_confidence       DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS ml_verdict          TEXT,
    ADD COLUMN IF NOT EXISTS ml_backend_version  TEXT;

INSERT INTO schema_migrations (version, name) VALUES (9, '009_prompt_ml_columns')
    ON CONFLICT (version) DO NOTHING;
