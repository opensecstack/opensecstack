CREATE TABLE sightings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_id         UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    platform       VARCHAR(50) NOT NULL CHECK (platform IN ('apiguard', 'irflow', 'manual')),
    resource_type  VARCHAR(100) NOT NULL,
    resource_id    VARCHAR(255) NOT NULL,
    observed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sightings_ioc ON sightings(ioc_id);
CREATE INDEX idx_sightings_platform ON sightings(platform);
CREATE INDEX idx_sightings_observed ON sightings(observed_at DESC);
CREATE INDEX idx_sightings_resource ON sightings(platform, resource_type, resource_id);
