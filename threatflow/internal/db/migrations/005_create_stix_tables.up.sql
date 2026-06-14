CREATE TABLE stix_bundles (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id       VARCHAR(128) NOT NULL UNIQUE,
    direction     VARCHAR(10) NOT NULL CHECK (direction IN ('import', 'export')),
    source        VARCHAR(255) NOT NULL,
    object_count  INT NOT NULL DEFAULT 0,
    bundle_hash   CHAR(64) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_stix_bundles_direction ON stix_bundles(direction);
CREATE INDEX idx_stix_bundles_source ON stix_bundles(source);
CREATE INDEX idx_stix_bundles_hash ON stix_bundles(bundle_hash);

CREATE TABLE stix_objects (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id      VARCHAR(128) NOT NULL UNIQUE,
    stix_type    VARCHAR(50) NOT NULL,
    bundle_id    UUID NOT NULL REFERENCES stix_bundles(id) ON DELETE CASCADE,
    content      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_stix_objects_type ON stix_objects(stix_type);
CREATE INDEX idx_stix_objects_bundle ON stix_objects(bundle_id);
CREATE INDEX idx_stix_objects_content ON stix_objects USING GIN (content);
