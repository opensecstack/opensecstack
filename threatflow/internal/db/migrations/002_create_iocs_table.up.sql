CREATE TABLE iocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id         VARCHAR(128) NOT NULL,
    type            VARCHAR(50) NOT NULL,
    value           TEXT NOT NULL,
    pattern         TEXT NOT NULL,
    pattern_hash    CHAR(64) NOT NULL UNIQUE,
    feed_id         UUID REFERENCES feeds(id) ON DELETE SET NULL,
    source          VARCHAR(255),
    confidence      INT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    description     TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    cve             VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_iocs_type ON iocs(type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_feed ON iocs(feed_id);
CREATE INDEX idx_iocs_confidence ON iocs(confidence DESC);
CREATE INDEX idx_iocs_stix_id ON iocs(stix_id);
CREATE INDEX idx_iocs_expires ON iocs(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_iocs_tags ON iocs USING GIN (tags);
CREATE INDEX idx_iocs_search ON iocs USING GIN (to_tsvector('english', coalesce(description, '') || ' ' || value));
