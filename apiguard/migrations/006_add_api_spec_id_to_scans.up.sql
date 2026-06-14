ALTER TABLE scans
    ADD COLUMN api_spec_id UUID REFERENCES api_specs(id) ON DELETE SET NULL;

CREATE INDEX idx_scans_api_spec_id ON scans(api_spec_id);

-- Also add owasp_category to findings (human-readable OWASP category name)
ALTER TABLE findings
    ADD COLUMN owasp_category TEXT;

-- Populate owasp_category from existing owasp_id values
UPDATE findings SET owasp_category = CASE owasp_id
    WHEN 'A1'  THEN 'Broken Object Level Authorization'
    WHEN 'A2'  THEN 'Broken Authentication'
    WHEN 'A3'  THEN 'Broken Object Property Level Authorization'
    WHEN 'A4'  THEN 'Unrestricted Resource Consumption'
    WHEN 'A5'  THEN 'Broken Function Level Authorization'
    WHEN 'A6'  THEN 'Unrestricted Access to Sensitive Business Flows'
    WHEN 'A7'  THEN 'Server Side Request Forgery'
    WHEN 'A8'  THEN 'Security Misconfiguration'
    WHEN 'A9'  THEN 'Improper Inventory Management'
    WHEN 'A10' THEN 'Unsafe Consumption of APIs'
    ELSE owasp_id
END;
