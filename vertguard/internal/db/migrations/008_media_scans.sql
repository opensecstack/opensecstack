-- VertGuard migration 008 — Module 1 (Media Authenticity) scan table.
--
-- Stores C2PA manifest verification results. No raw media content is
-- ever persisted; privacy by schema design (only hashes + metadata).
--
-- Idempotent — safe to run against a fresh or already-migrated database.

CREATE TABLE IF NOT EXISTS media_scans (
    id              UUID            PRIMARY KEY,
    scan_id         TEXT            NOT NULL UNIQUE,
    file_hash       TEXT            NOT NULL,           -- SHA-256 hex of uploaded file
    file_size       BIGINT          NOT NULL,
    content_hint    TEXT,                               -- filename or MIME type hint
    has_manifest    BOOLEAN         NOT NULL DEFAULT FALSE,
    signature_valid BOOLEAN         NOT NULL DEFAULT FALSE,
    signer          TEXT,                               -- CN from signing certificate
    claims_count    INT             NOT NULL DEFAULT 0,
    format          TEXT,                               -- detected file format
    errors          TEXT[]          NOT NULL DEFAULT '{}',
    warnings        TEXT[]          NOT NULL DEFAULT '{}',
    duration_ms     NUMERIC(8,3),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_scans_created_at ON media_scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_scans_file_hash  ON media_scans (file_hash);

INSERT INTO schema_migrations (version, name) VALUES (8, '008_media_scans')
    ON CONFLICT (version) DO NOTHING;
