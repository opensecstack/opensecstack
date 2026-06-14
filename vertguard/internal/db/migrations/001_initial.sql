-- VertGuard initial schema (Phase 4.1)
--
-- Idempotent — safe to apply against a fresh or up-to-date database.
-- No raw-content columns: privacy by schema design.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INT         NOT NULL PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── Module 3 (Prompt Injection) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS prompt_scans (
    id             UUID        PRIMARY KEY,
    scan_id        TEXT        NOT NULL UNIQUE,
    classification TEXT        NOT NULL,                  -- CLEAN | SUSPICIOUS | BLOCKED
    confidence     NUMERIC(4,3) NOT NULL,
    input_hash     TEXT        NOT NULL,                  -- SHA-256 hex of input (no raw content)
    input_length   INT         NOT NULL,
    context        TEXT,                                  -- user_chat_input, untrusted_third_party, etc.
    match_count    INT         NOT NULL DEFAULT 0,
    matches        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    worm_entry_id  TEXT,                                  -- CITADEL WORM reference (nullable if standalone)
    duration_ms    NUMERIC(8,3),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_prompt_scans_classification ON prompt_scans (classification);
CREATE INDEX IF NOT EXISTS idx_prompt_scans_created_at    ON prompt_scans (created_at DESC);

-- ─── Module 4 (AI Threat Feed) ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_iocs (
    id              UUID        PRIMARY KEY,
    pattern_value   TEXT        NOT NULL,                 -- canonical pattern ID
    type            TEXT        NOT NULL DEFAULT 'ai_attack_pattern',
    source          TEXT        NOT NULL,
    source_ref      TEXT,
    atlas_technique TEXT,                                 -- AML.T####
    confidence      NUMERIC(3,2) NOT NULL,
    severity        TEXT        NOT NULL DEFAULT 'medium',
    description     TEXT,
    "references"    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    deprecated      BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (pattern_value, source)
);

CREATE INDEX IF NOT EXISTS idx_threat_iocs_atlas_tech  ON threat_iocs (atlas_technique);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_last_seen   ON threat_iocs (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_confidence  ON threat_iocs (confidence DESC);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_tags        ON threat_iocs USING GIN (tags);

CREATE TABLE IF NOT EXISTS atlas_mappings (
    technique_id      TEXT        PRIMARY KEY,            -- AML.T####
    name              TEXT        NOT NULL,
    description       TEXT,
    tactic_id         TEXT        NOT NULL,               -- AML.TA####
    tactic_name       TEXT        NOT NULL,
    atlas_url         TEXT,
    synced_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_atlas_mappings_tactic ON atlas_mappings (tactic_id);

-- ─── Module 1 (Media Authenticity) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS media_verifications (
    id               UUID        PRIMARY KEY,
    scan_id          TEXT        NOT NULL UNIQUE,
    classification   TEXT        NOT NULL,                -- authentic | unauthentic | unknown
    content_type     TEXT,
    content_hash     TEXT        NOT NULL,                -- TripleHash hex
    content_size     BIGINT      NOT NULL,
    provenance_chain JSONB       DEFAULT '[]'::jsonb,
    signer           TEXT,
    reason           TEXT,                                -- e.g. "no C2PA manifest present"
    worm_entry_id    TEXT,
    duration_ms      NUMERIC(8,3),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_verifications_created ON media_verifications (created_at DESC);

-- ─── Bookkeeping ──────────────────────────────────────────────────────

INSERT INTO schema_migrations (version, name) VALUES (1, '001_initial')
    ON CONFLICT (version) DO NOTHING;
