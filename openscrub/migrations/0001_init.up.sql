-- 0001_init — OpenScrub control-plane schema.
--
-- Tables:
--   rules            — active blocklist + ratelimit rules pushed to the data plane
--   ioc_ingest_log   — audit log of ThreatFlow IOC pulls
--   mitigations      — observed drop/ratelimit windows (CITADEL evidence source)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type         TEXT NOT NULL CHECK (type IN ('blocklist', 'ratelimit', 'syncookie')),
    cidr         CIDR,
    pps          INTEGER,
    port         INTEGER CHECK (port IS NULL OR (port > 0 AND port < 65536)),
    ttl_seconds  INTEGER NOT NULL CHECK (ttl_seconds > 0),
    source       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    created_by   UUID,
    CONSTRAINT blocklist_requires_cidr
        CHECK (type <> 'blocklist' OR cidr IS NOT NULL),
    CONSTRAINT ratelimit_requires_cidr_and_pps
        CHECK (type <> 'ratelimit'
            OR (cidr IS NOT NULL AND pps IS NOT NULL AND pps > 0)),
    CONSTRAINT syncookie_requires_port
        CHECK (type <> 'syncookie' OR port IS NOT NULL)
);

CREATE INDEX idx_rules_expires_at ON rules (expires_at);
CREATE INDEX idx_rules_source     ON rules (source);
CREATE INDEX idx_rules_type       ON rules (type);
CREATE INDEX idx_rules_cidr_gist  ON rules USING gist (cidr inet_ops) WHERE cidr IS NOT NULL;
CREATE INDEX idx_rules_port       ON rules (port) WHERE port IS NOT NULL;

CREATE TABLE ioc_ingest_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source        TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    count         INTEGER NOT NULL,
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, bundle_sha256)
);

CREATE INDEX idx_ioc_ingest_log_at ON ioc_ingest_log (ingested_at DESC);

CREATE TABLE mitigations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID NOT NULL REFERENCES rules (id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ,
    packets_dropped BIGINT NOT NULL DEFAULT 0,
    bytes_dropped   BIGINT NOT NULL DEFAULT 0,
    src_ip          INET,
    emitted         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_mitigations_rule    ON mitigations (rule_id);
CREATE INDEX idx_mitigations_started ON mitigations (started_at DESC);
