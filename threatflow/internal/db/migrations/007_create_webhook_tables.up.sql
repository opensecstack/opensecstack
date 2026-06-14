-- Webhook subscribers register to receive IOC / bundle / sighting events.
CREATE TABLE webhook_subscribers (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(255) NOT NULL UNIQUE,
    platform         VARCHAR(50) NOT NULL CHECK (platform IN (
        'apiguard', 'irflow', 'nis2compass', 'external'
    )),
    url              TEXT NOT NULL,
    secret           TEXT NOT NULL,
    event_types      TEXT[] NOT NULL DEFAULT '{}',
    min_confidence   INT NOT NULL DEFAULT 0 CHECK (min_confidence BETWEEN 0 AND 100),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_subs_platform ON webhook_subscribers(platform);
CREATE INDEX idx_webhook_subs_enabled ON webhook_subscribers(enabled) WHERE enabled = TRUE;

-- Every delivery attempt is logged so retries are idempotent and operators
-- can audit the outbound stream.
CREATE TABLE webhook_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id   UUID NOT NULL REFERENCES webhook_subscribers(id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL,
    event_id        UUID NOT NULL,
    payload         JSONB NOT NULL,
    status          VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'delivered', 'failed', 'retrying')),
    attempt_count   INT NOT NULL DEFAULT 0,
    last_status     INT,
    last_error      TEXT,
    last_attempt_at TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT webhook_deliveries_dedup UNIQUE (subscriber_id, event_id)
);

CREATE INDEX idx_webhook_deliv_status ON webhook_deliveries(status) WHERE status IN ('pending', 'retrying');
CREATE INDEX idx_webhook_deliv_sub ON webhook_deliveries(subscriber_id);
CREATE INDEX idx_webhook_deliv_event ON webhook_deliveries(event_id);
