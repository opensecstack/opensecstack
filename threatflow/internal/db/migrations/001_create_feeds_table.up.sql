CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE feeds (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              VARCHAR(255) NOT NULL UNIQUE,
    feed_type         VARCHAR(50) NOT NULL CHECK (feed_type IN ('taxii21', 'csv', 'misp', 'manual')),
    url               TEXT,
    poll_interval     INTERVAL NOT NULL DEFAULT INTERVAL '1 hour',
    confidence_base   INT NOT NULL DEFAULT 50 CHECK (confidence_base BETWEEN 0 AND 100),
    accuracy_ratio    DOUBLE PRECISION NOT NULL DEFAULT 1.0 CHECK (accuracy_ratio BETWEEN 0.0 AND 1.0),
    last_poll_at      TIMESTAMPTZ,
    last_poll_count   INT NOT NULL DEFAULT 0,
    error_count       INT NOT NULL DEFAULT 0,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_feeds_enabled ON feeds(enabled) WHERE enabled = TRUE;
CREATE INDEX idx_feeds_type ON feeds(feed_type);
