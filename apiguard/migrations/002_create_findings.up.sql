CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE finding_status AS ENUM ('open', 'confirmed', 'false_positive', 'accepted', 'fixed');

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    -- OWASP classification
    owasp_id VARCHAR(10) NOT NULL, -- A1, A2, ..., A10
    module_id VARCHAR(50) NOT NULL, -- a1_bola, a2_auth, etc.

    -- Finding details
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity finding_severity NOT NULL,

    -- CVSS
    cvss_score DECIMAL(3,1) NOT NULL DEFAULT 0.0,
    cvss_vector VARCHAR(100),

    -- Location
    endpoint_path TEXT NOT NULL,
    endpoint_method VARCHAR(10) NOT NULL,

    -- Evidence
    evidence_request TEXT, -- HTTP request that triggered the finding
    evidence_response TEXT, -- HTTP response proving the finding
    evidence_json JSONB, -- Structured evidence

    -- Remediation
    remediation TEXT,

    -- Triage
    status finding_status NOT NULL DEFAULT 'open',
    triaged_by VARCHAR(255),
    triaged_at TIMESTAMPTZ,
    triage_note TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_module_id ON findings(module_id);
CREATE INDEX idx_findings_owasp_id ON findings(owasp_id);
