-- =============================================================================
-- APIGuard Integration Test Seed Data
-- =============================================================================
-- Minimal, predictable dataset for integration tests.
-- All UUIDs are fixed so test assertions can reference them directly.
--
-- Scope:
--   - 1 api_spec  (OpenAPI 3.0)
--   - 1 completed scan with 3 findings (1 critical, 1 high, 1 medium)
--   - No audit_log entries — tests manage their own audit events
--
-- Re-runnable: all inserts use ON CONFLICT DO NOTHING.
--
-- Usage:
--   psql $TEST_DATABASE_URL -f scripts/seed_test.sql
--
-- Typical test lifecycle:
--   1. Apply migrations
--   2. Run seed_test.sql once before the test suite
--   3. Each test that mutates data should run db_reset.sql + seed_test.sql
--      in its setup, or use a transaction that is rolled back after the test.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- API SPEC
-- Test constant: SPEC_ID = 'a0000000-0000-0000-0000-000000000001'
-- -----------------------------------------------------------------------------

INSERT INTO api_specs (
    id,
    spec_hash,
    spec_url,
    spec_format,
    title,
    version,
    base_url,
    endpoint_count,
    auth_schemes,
    raw_spec,
    parsed_ir,
    created_at
) VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'https://test-api.example.com/openapi.json',
    'openapi3',
    'Test API',
    '1.0.0',
    'https://test-api.example.com',
    5,
    '["bearerAuth"]',
    '{"openapi":"3.0.0","info":{"title":"Test API","version":"1.0.0"}}',
    '{
        "version": "3.0.0",
        "format": "openapi3",
        "endpoints": [
            {"path": "/users/{id}", "method": "GET", "auth_required": true},
            {"path": "/admin/users", "method": "POST", "auth_required": true},
            {"path": "/auth/login", "method": "POST", "auth_required": false}
        ],
        "auth_schemes": [{"type": "http", "scheme": "bearer", "name": "bearerAuth"}]
    }',
    '2024-01-01T00:00:00Z'
)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- SCAN
-- Test constant: SCAN_ID = 'b0000000-0000-0000-0000-000000000001'
-- -----------------------------------------------------------------------------

INSERT INTO scans (
    id,
    api_spec_id,
    spec_url,
    spec_hash,
    target_url,
    status,
    modules,
    started_at,
    completed_at,
    created_at,
    config_json,
    total_findings,
    critical_count,
    high_count,
    medium_count,
    low_count,
    info_count,
    auth_type,
    error_message
) VALUES (
    'b0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'https://test-api.example.com/openapi.json',
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'https://test-api.example.com',
    'completed',
    ARRAY['a1_bola', 'a2_auth', 'a4_rate_limit'],
    '2024-01-01T01:00:00Z',
    '2024-01-01T01:15:00Z',
    '2024-01-01T00:55:00Z',
    '{"timeout_seconds": 30, "max_concurrent_requests": 5}',
    3,
    1,
    1,
    1,
    0,
    0,
    'bearer',
    NULL
)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- FINDINGS (3 total, attached to the test scan)
-- Test constants:
--   FINDING_CRITICAL_ID = 'c0000000-0000-0000-0000-000000000001'
--   FINDING_HIGH_ID     = 'c0000000-0000-0000-0000-000000000002'
--   FINDING_MEDIUM_ID   = 'c0000000-0000-0000-0000-000000000003'
-- -----------------------------------------------------------------------------

INSERT INTO findings (
    id,
    scan_id,
    owasp_id,
    owasp_category,
    module_id,
    title,
    description,
    severity,
    cvss_score,
    cvss_vector,
    endpoint_path,
    endpoint_method,
    evidence_request,
    evidence_response,
    evidence_json,
    remediation,
    status,
    triaged_by,
    triaged_at,
    triage_note,
    created_at
) VALUES

-- Critical finding
(
    'c0000000-0000-0000-0000-000000000001',
    'b0000000-0000-0000-0000-000000000001',
    'A1',
    'Broken Object Level Authorization',
    'a1_bola',
    'Broken Object Level Authorization on GET /users/{id}',
    'User A can retrieve User B''s profile by substituting the id parameter. No ownership check is enforced.',
    'critical',
    9.1,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    '/users/{id}',
    'GET',
    E'GET /users/2 HTTP/1.1\nHost: test-api.example.com\nAuthorization: Bearer test-token-user-1',
    E'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":2,"email":"user2@example.com","role":"user"}',
    '{"cross_user_access": true, "response_status": 200, "expected_status": 403}',
    'Enforce object-level authorization checks on all resource endpoints.',
    'open',
    NULL,
    NULL,
    NULL,
    '2024-01-01T01:15:00Z'
),

-- High finding
(
    'c0000000-0000-0000-0000-000000000002',
    'b0000000-0000-0000-0000-000000000001',
    'A2',
    'Broken Authentication',
    'a2_auth',
    'Expired JWT Token Accepted on GET /users/{id}',
    'An expired JWT token (exp claim in the past) was accepted and the request was processed successfully.',
    'high',
    7.4,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    '/users/{id}',
    'GET',
    E'GET /users/1 HTTP/1.1\nHost: test-api.example.com\nAuthorization: Bearer expired-test-token',
    E'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":1,"email":"user1@example.com"}',
    '{"token_exp": "2023-01-01T00:00:00Z", "exp_validation_bypassed": true, "response_status": 200}',
    'Enable JWT exp claim validation in the authentication middleware.',
    'open',
    NULL,
    NULL,
    NULL,
    '2024-01-01T01:15:00Z'
),

-- Medium finding
(
    'c0000000-0000-0000-0000-000000000003',
    'b0000000-0000-0000-0000-000000000001',
    'A4',
    'Unrestricted Resource Consumption',
    'a4_rate_limit',
    'No Rate Limiting on POST /auth/login',
    '200 consecutive login attempts completed in under 10 seconds without triggering rate limiting or account lockout.',
    'medium',
    5.3,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    '/auth/login',
    'POST',
    E'POST /auth/login HTTP/1.1\nHost: test-api.example.com\nContent-Type: application/json\n\n{"email":"user@example.com","password":"wrong"}',
    E'HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\n{"error":"invalid_credentials"}',
    '{"requests_sent": 200, "duration_seconds": 9, "rate_limit_triggered": false, "lockout_triggered": false}',
    'Implement rate limiting on the login endpoint (e.g., 5 attempts per minute per IP).',
    'open',
    NULL,
    NULL,
    NULL,
    '2024-01-01T01:15:00Z'
)

ON CONFLICT (id) DO NOTHING;

COMMIT;
