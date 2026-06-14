-- VertGuard Module 5 (Phishing Detection) — rule-based v1.
--
-- Idempotent. Privacy-by-schema: input_hash only, never raw payload.

CREATE TABLE IF NOT EXISTS phishing_scans (
    id              UUID         PRIMARY KEY,
    scan_id         TEXT         NOT NULL UNIQUE,
    classification  TEXT         NOT NULL,                  -- CLEAN | SUSPICIOUS | BLOCKED
    confidence      NUMERIC(4,3) NOT NULL,
    input_hash      TEXT         NOT NULL,                  -- SHA-256 hex
    input_length    INT          NOT NULL,
    kind            TEXT         NOT NULL,                  -- url | email | html
    indicator_count INT          NOT NULL DEFAULT 0,
    indicators      JSONB        NOT NULL DEFAULT '[]'::jsonb,
    worm_entry_id   TEXT,
    duration_ms     NUMERIC(8,3),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_phishing_scans_created_at
    ON phishing_scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phishing_scans_class_created
    ON phishing_scans (classification, created_at DESC);

INSERT INTO schema_migrations (version, name) VALUES (4, '004_phishing_scans')
    ON CONFLICT (version) DO NOTHING;
