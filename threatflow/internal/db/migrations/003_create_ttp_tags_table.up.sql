CREATE TABLE ttp_tags (
    ioc_id        UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    technique_id  VARCHAR(20) NOT NULL,
    source        VARCHAR(50) NOT NULL CHECK (source IN ('auto', 'feed', 'manual')),
    confidence    INT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ioc_id, technique_id)
);

CREATE INDEX idx_ttp_tags_technique ON ttp_tags(technique_id);
