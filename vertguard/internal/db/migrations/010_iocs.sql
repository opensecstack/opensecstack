-- VertGuard migration 010 — VG-006 persistent IOC store + community-feed
-- sync audit log.
--
-- Idempotent. Mirrors the openscrub IOC pull-audit shape so dashboards
-- can correlate cross-product feed health.

CREATE TABLE IF NOT EXISTS iocs (
    id          UUID         PRIMARY KEY,
    kind        TEXT         NOT NULL CHECK (kind IN
                                ('ip','cidr','domain','url','hash_sha256','hash_md5')),
    value       TEXT         NOT NULL,
    source      TEXT         NOT NULL,
    confidence  REAL         NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
    tags        TEXT[]       NOT NULL DEFAULT '{}',
    first_seen  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    tenant      TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (kind, value, tenant)
);

CREATE INDEX IF NOT EXISTS idx_iocs_value      ON iocs (value);
CREATE INDEX IF NOT EXISTS idx_iocs_kind       ON iocs (kind);
CREATE INDEX IF NOT EXISTS idx_iocs_source     ON iocs (source);
CREATE INDEX IF NOT EXISTS idx_iocs_expires_at ON iocs (expires_at);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen  ON iocs (last_seen DESC);

CREATE TABLE IF NOT EXISTS ioc_pull_audit (
    id           UUID         PRIMARY KEY,
    source       TEXT         NOT NULL,
    started_at   TIMESTAMPTZ  NOT NULL,
    finished_at  TIMESTAMPTZ  NOT NULL,
    fetched      INT          NOT NULL DEFAULT 0,
    inserted     INT          NOT NULL DEFAULT 0,
    updated      INT          NOT NULL DEFAULT 0,
    skipped      INT          NOT NULL DEFAULT 0,
    error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_ioc_pull_audit_source_started
    ON ioc_pull_audit (source, started_at DESC);

INSERT INTO schema_migrations (version, name) VALUES (10, '010_iocs')
    ON CONFLICT (version) DO NOTHING;
