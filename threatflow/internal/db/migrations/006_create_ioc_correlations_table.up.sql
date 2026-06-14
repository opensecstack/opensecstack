CREATE TABLE ioc_correlations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ioc_id  UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    target_ioc_id  UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    relationship   VARCHAR(50) NOT NULL CHECK (relationship IN (
        'duplicate',
        'resolves-to',
        'subdomain-of',
        'shares-cve',
        'same-network',
        'related-to'
    )),
    confidence     INT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    evidence       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ioc_correlations_distinct CHECK (source_ioc_id <> target_ioc_id),
    CONSTRAINT ioc_correlations_unique UNIQUE (source_ioc_id, target_ioc_id, relationship)
);

CREATE INDEX idx_ioc_corr_source ON ioc_correlations(source_ioc_id);
CREATE INDEX idx_ioc_corr_target ON ioc_correlations(target_ioc_id);
CREATE INDEX idx_ioc_corr_relationship ON ioc_correlations(relationship);
