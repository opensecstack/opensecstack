-- =============================================================================
-- APIGuard Development Seed Data
-- =============================================================================
-- Populates realistic data for local development.
-- Safe to re-run: all inserts use ON CONFLICT DO NOTHING (idempotent).
--
-- UUIDs are hard-coded so references stay stable across resets.
-- Run after all migrations have been applied.
--
-- Usage:
--   psql $DATABASE_URL -f scripts/seed.sql
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. API SPECS
-- -----------------------------------------------------------------------------
-- Two specs: one OpenAPI 3.0 (Petstore-like), one Swagger 2.0 (legacy).

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
) VALUES
(
    -- Spec 1: OpenAPI 3.0 — Petstore-like e-commerce API
    '00000000-0000-0000-0000-000000000001',
    'a3f1c2d4e5b6789012345678901234567890abcdef1234567890abcdef123456',
    'https://api.petstore-example.com/openapi.json',
    'openapi3',
    'Petstore E-Commerce API',
    '3.1.0',
    'https://api.petstore-example.com',
    24,
    '["bearerAuth", "apiKeyAuth"]',
    '{"openapi":"3.1.0","info":{"title":"Petstore E-Commerce API","version":"3.1.0"},"paths":{"/api/users/{id}":{"get":{}}}}',
    '{
        "version": "3.1.0",
        "format": "openapi3",
        "endpoints": [
            {"path": "/api/users", "method": "GET", "auth_required": true},
            {"path": "/api/users/{id}", "method": "GET", "auth_required": true},
            {"path": "/api/users/{id}", "method": "PUT", "auth_required": true},
            {"path": "/api/admin/users", "method": "POST", "auth_required": false},
            {"path": "/api/admin/users/{id}", "method": "DELETE", "auth_required": true},
            {"path": "/api/orders/{id}", "method": "GET", "auth_required": true},
            {"path": "/api/auth/login", "method": "POST", "auth_required": false}
        ],
        "auth_schemes": [
            {"type": "http", "scheme": "bearer", "name": "bearerAuth"},
            {"type": "apiKey", "in": "header", "name": "X-API-Key"}
        ]
    }',
    NOW() - INTERVAL '7 days'
),
(
    -- Spec 2: Swagger 2.0 — legacy inventory management API
    '00000000-0000-0000-0000-000000000002',
    'b7e2d3f4a5c6890123456789012345678901bcdef2345678901bcdef234567',
    'https://legacy.inventory-api.internal/swagger.json',
    'swagger2',
    'Legacy Inventory Management API',
    '1.4.2',
    'https://legacy.inventory-api.internal',
    11,
    '["basicAuth"]',
    '{"swagger":"2.0","info":{"title":"Legacy Inventory Management API","version":"1.4.2"},"paths":{"/v1/items":{"get":{}}}}',
    '{
        "version": "2.0",
        "format": "swagger2",
        "endpoints": [
            {"path": "/v1/items", "method": "GET", "auth_required": true},
            {"path": "/v1/items/{id}", "method": "GET", "auth_required": true},
            {"path": "/v1/items", "method": "POST", "auth_required": true},
            {"path": "/v1/suppliers", "method": "GET", "auth_required": true}
        ],
        "auth_schemes": [
            {"type": "basic", "name": "basicAuth"}
        ]
    }',
    NOW() - INTERVAL '30 days'
)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 2. SCANS
-- -----------------------------------------------------------------------------
-- Three scans: completed (with findings), running, failed.

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
) VALUES
(
    -- Scan 1: Completed — 8 findings across the Petstore API
    '10000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'https://api.petstore-example.com/openapi.json',
    'a3f1c2d4e5b6789012345678901234567890abcdef1234567890abcdef123456',
    'https://api.petstore-example.com',
    'completed',
    ARRAY['a1_bola','a2_auth','a3_mass_assignment','a4_rate_limit','a5_function_auth','a8_misconfiguration'],
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour',
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes',
    NOW() - INTERVAL '2 days',
    '{
        "timeout_seconds": 30,
        "max_concurrent_requests": 10,
        "follow_redirects": true,
        "auth": {"type": "bearer", "token_env": "APIGUARD_BEARER_TOKEN"},
        "modules": {
            "a1_bola": {"enabled": true, "fuzz_ids": true},
            "a2_auth": {"enabled": true, "test_expired_tokens": true},
            "a3_mass_assignment": {"enabled": true},
            "a4_rate_limit": {"enabled": true, "request_count": 100},
            "a5_function_auth": {"enabled": true},
            "a8_misconfiguration": {"enabled": true, "check_headers": true}
        }
    }',
    8,
    2,
    3,
    2,
    1,
    0,
    'bearer',
    NULL
),
(
    -- Scan 2: Running — currently active against the Petstore API
    '10000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'https://api.petstore-example.com/openapi.json',
    'a3f1c2d4e5b6789012345678901234567890abcdef1234567890abcdef123456',
    'https://api.petstore-example.com',
    'running',
    ARRAY['a1_bola','a2_auth','a4_rate_limit'],
    NOW() - INTERVAL '5 minutes',
    NULL,
    NOW() - INTERVAL '6 minutes',
    '{
        "timeout_seconds": 30,
        "max_concurrent_requests": 5,
        "follow_redirects": true,
        "auth": {"type": "bearer", "token_env": "APIGUARD_BEARER_TOKEN"},
        "modules": {
            "a1_bola": {"enabled": true, "fuzz_ids": true},
            "a2_auth": {"enabled": true},
            "a4_rate_limit": {"enabled": true, "request_count": 50}
        }
    }',
    0,
    0,
    0,
    0,
    0,
    0,
    'bearer',
    NULL
),
(
    -- Scan 3: Failed — legacy API scan that could not connect
    '10000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000002',
    'https://legacy.inventory-api.internal/swagger.json',
    'b7e2d3f4a5c6890123456789012345678901bcdef2345678901bcdef234567',
    'https://legacy.inventory-api.internal',
    'failed',
    ARRAY['a1_bola','a2_auth','a5_function_auth'],
    NOW() - INTERVAL '1 day' + INTERVAL '30 minutes',
    NULL,
    NOW() - INTERVAL '1 day',
    '{
        "timeout_seconds": 15,
        "max_concurrent_requests": 3,
        "follow_redirects": false,
        "auth": {"type": "basic", "username_env": "LEGACY_API_USER", "password_env": "LEGACY_API_PASS"},
        "modules": {
            "a1_bola": {"enabled": true},
            "a2_auth": {"enabled": true},
            "a5_function_auth": {"enabled": true}
        }
    }',
    0,
    0,
    0,
    0,
    0,
    0,
    'basic',
    'connection refused: dial tcp legacy.inventory-api.internal:443: connect: connection refused — host unreachable from scanner network'
)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 3. FINDINGS (8 total, attached to completed scan 1)
-- -----------------------------------------------------------------------------
-- Severity distribution: 2 critical, 3 high, 2 medium, 1 low.

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

-- Finding 1: CRITICAL — BOLA on GET /api/users/{id}
(
    '20000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001',
    'A1',
    'Broken Object Level Authorization',
    'a1_bola',
    'Broken Object Level Authorization on GET /api/users/{id}',
    'The endpoint GET /api/users/{id} returns full user profile data when accessed with a valid bearer token belonging to a different user. User A (id=1001) was able to retrieve the complete profile of User B (id=1002) including email, phone, and address — without any ownership check. This is a textbook BOLA vulnerability (OWASP API1:2023).',
    'critical',
    9.1,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    '/api/users/{id}',
    'GET',
    E'GET /api/users/1002 HTTP/1.1\nHost: api.petstore-example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwibmFtZSI6IlVzZXIgQSIsImlhdCI6MTcxMDAwMDAwMH0.SEED_TOKEN_USER_A\nAccept: application/json',
    E'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":1002,"email":"userb@example.com","phone":"+1-555-0199","address":{"street":"456 Oak Ave","city":"Springfield"},"role":"user","created_at":"2024-01-15T09:00:00Z"}',
    '{
        "attacked_resource_id": "1002",
        "attacker_resource_id": "1001",
        "fields_exposed": ["email", "phone", "address", "role"],
        "cross_user_access": true,
        "response_status": 200,
        "expected_status": 403
    }',
    'Implement object-level authorization checks on every endpoint that accesses user-owned resources. Verify that the authenticated user''s identity (from the JWT sub claim) matches the requested resource owner before returning data. Consider using a centralized authorization middleware rather than per-handler checks.',
    'confirmed',
    'dev@apiguard.local',
    NOW() - INTERVAL '1 day 22 hours',
    'Confirmed exploitable. Affects all /api/users/{id} variants. Ticket filed: SEC-101.',
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 2: CRITICAL — Missing Authentication on POST /api/admin/users
(
    '20000000-0000-0000-0000-000000000002',
    '10000000-0000-0000-0000-000000000001',
    'A2',
    'Broken Authentication',
    'a2_auth',
    'Missing Authentication on POST /api/admin/users',
    'The administrative endpoint POST /api/admin/users accepts and processes requests without any Authorization header. Sending a well-formed user creation payload without credentials results in HTTP 201 Created and a new user account being created with the specified role. An unauthenticated attacker can create arbitrary user accounts including admin-privileged accounts.',
    'critical',
    9.1,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    '/api/admin/users',
    'POST',
    E'POST /api/admin/users HTTP/1.1\nHost: api.petstore-example.com\nContent-Type: application/json\nContent-Length: 89\n\n{"email":"attacker@evil.com","password":"P@ssw0rd!","role":"admin","name":"Evil Admin"}',
    E'HTTP/1.1 201 Created\nContent-Type: application/json\nLocation: /api/admin/users/9999\n\n{"id":9999,"email":"attacker@evil.com","role":"admin","created_at":"2024-03-10T14:22:00Z"}',
    '{
        "auth_header_present": false,
        "response_status": 201,
        "expected_status": 401,
        "created_resource_id": 9999,
        "created_role": "admin",
        "unauthenticated_write": true
    }',
    'Require authentication on all /api/admin/* endpoints without exception. Apply a router-level middleware that validates the Authorization header before any admin handler executes. Audit all admin routes for missing auth guards. Add integration tests that assert 401 is returned for unauthenticated requests to every admin endpoint.',
    'open',
    NULL,
    NULL,
    NULL,
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 3: HIGH — Expired JWT Token Accepted
(
    '20000000-0000-0000-0000-000000000003',
    '10000000-0000-0000-0000-000000000001',
    'A2',
    'Broken Authentication',
    'a2_auth',
    'Expired JWT Token Accepted on GET /api/orders/{id}',
    'The endpoint GET /api/orders/{id} accepts JWT tokens whose exp claim has passed. A token issued 48 hours ago with an expiry of 1 hour was replayed and the server returned HTTP 200 with full order data. The server is not validating the exp claim, allowing indefinite token reuse after logout or expiry.',
    'high',
    7.4,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    '/api/orders/{id}',
    'GET',
    E'GET /api/orders/5543 HTTP/1.1\nHost: api.petstore-example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwiZXhwIjoxNzA5OTAwMDAwLCJpYXQiOjE3MDk4OTY0MDB9.EXPIRED_SEED_TOKEN\nAccept: application/json',
    E'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":5543,"user_id":1001,"status":"shipped","items":[{"sku":"PET-001","qty":2,"price":29.99}],"total":59.98}',
    '{
        "token_issued_at": "2024-03-08T10:00:00Z",
        "token_exp": "2024-03-08T11:00:00Z",
        "request_time": "2024-03-10T14:00:00Z",
        "token_age_hours": 52,
        "exp_validation_bypassed": true,
        "response_status": 200,
        "expected_status": 401
    }',
    'Enable JWT expiry validation in the token verification middleware. Ensure the exp claim is checked on every authenticated request. Implement a token revocation list (Redis) to handle logout and session invalidation. Set token lifetimes to match your session policy (e.g., 15 minutes for access tokens, 7 days for refresh tokens).',
    'open',
    NULL,
    NULL,
    NULL,
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 4: HIGH — Admin Endpoint Accessible Without Function-Level Auth
(
    '20000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000001',
    'A5',
    'Broken Function Level Authorization',
    'a5_function_auth',
    'Admin Endpoint Accessible Without Authorization on DELETE /api/admin/users/{id}',
    'The DELETE /api/admin/users/{id} endpoint successfully deletes user accounts when called by a token belonging to a regular (non-admin) user role. The server authenticates the request (bearer token is validated) but does not check whether the caller holds an admin or moderator role before executing the destructive operation. A regular user can delete any other user account.',
    'high',
    7.1,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H',
    '/api/admin/users/{id}',
    'DELETE',
    E'DELETE /api/admin/users/1005 HTTP/1.1\nHost: api.petstore-example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MTAwMDAwMDB9.SEED_TOKEN_REGULAR_USER\nAccept: application/json',
    E'HTTP/1.1 204 No Content\n',
    '{
        "caller_role": "user",
        "required_role": "admin",
        "target_resource_id": 1005,
        "resource_deleted": true,
        "response_status": 204,
        "expected_status": 403
    }',
    'Implement role-based access control (RBAC) checks at the function level for all /api/admin/* endpoints. Verify the caller''s role claim from the JWT before executing privileged operations. A middleware pattern is recommended: apply an admin-only guard to the entire /api/admin router rather than relying on per-handler checks.',
    'open',
    NULL,
    NULL,
    NULL,
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 5: HIGH — Mass Assignment on PUT /api/users/{id}
(
    '20000000-0000-0000-0000-000000000005',
    '10000000-0000-0000-0000-000000000001',
    'A3',
    'Broken Object Property Level Authorization',
    'a3_mass_assignment',
    'Mass Assignment — Privileged Fields Accepted on PUT /api/users/{id}',
    'The PUT /api/users/{id} endpoint accepts and persists arbitrary fields from the request body, including privileged fields that should be server-controlled. Submitting a payload containing "role": "admin" and "is_verified": true results in the user record being updated with admin privileges and a verified status — fields that should only be set by internal processes or admin actions.',
    'high',
    7.5,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    '/api/users/{id}',
    'PUT',
    E'PUT /api/users/1001 HTTP/1.1\nHost: api.petstore-example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MTAwMDAwMDB9.SEED_TOKEN_USER_A\nContent-Type: application/json\n\n{"name":"Updated Name","email":"user@example.com","role":"admin","is_verified":true,"credit_balance":99999}',
    E'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":1001,"name":"Updated Name","email":"user@example.com","role":"admin","is_verified":true,"credit_balance":99999,"updated_at":"2024-03-10T14:30:00Z"}',
    '{
        "mass_assigned_fields": ["role", "is_verified", "credit_balance"],
        "privileged_field_accepted": true,
        "role_escalated_to": "admin",
        "response_status": 200,
        "expected_behavior": "privileged fields should be stripped or rejected with 422"
    }',
    'Implement an allowlist of fields that users are permitted to update on their own profile (e.g., name, email, phone). Strip or reject any fields outside this allowlist before processing. Use a dedicated DTO/request struct that only exposes permitted fields — do not bind the request body directly to the database model. Add validation tests for privilege escalation via mass assignment.',
    'open',
    NULL,
    NULL,
    NULL,
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 6: MEDIUM — No Rate Limiting on POST /api/auth/login
(
    '20000000-0000-0000-0000-000000000006',
    '10000000-0000-0000-0000-000000000001',
    'A4',
    'Unrestricted Resource Consumption',
    'a4_rate_limit',
    'No Rate Limiting on POST /api/auth/login',
    'The authentication endpoint POST /api/auth/login does not enforce rate limiting or account lockout. The scanner sent 500 consecutive login attempts within 60 seconds for the same account without triggering any throttling, CAPTCHA challenge, or temporary lockout. This enables brute-force and credential stuffing attacks at scale.',
    'medium',
    5.3,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    '/api/auth/login',
    'POST',
    E'POST /api/auth/login HTTP/1.1\nHost: api.petstore-example.com\nContent-Type: application/json\n\n{"email":"target@example.com","password":"attempt-001"}',
    E'HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\n{"error":"invalid_credentials","message":"Email or password is incorrect"}',
    '{
        "requests_sent": 500,
        "duration_seconds": 60,
        "rate_limit_triggered": false,
        "lockout_triggered": false,
        "responses": {"401": 498, "200": 2},
        "x_ratelimit_header_present": false
    }',
    'Implement rate limiting on the authentication endpoint using a sliding-window algorithm keyed on IP address and/or account identifier. Enforce account lockout (e.g., 5 failed attempts → 15-minute lockout) and add exponential back-off. Return 429 Too Many Requests with a Retry-After header when limits are exceeded. Consider integrating with a WAF or API gateway for network-level protection.',
    'open',
    NULL,
    NULL,
    NULL,
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 7: MEDIUM — Security Headers Missing
(
    '20000000-0000-0000-0000-000000000007',
    '10000000-0000-0000-0000-000000000001',
    'A8',
    'Security Misconfiguration',
    'a8_misconfiguration',
    'Security Headers Missing on GET /api/users',
    'Responses from GET /api/users are missing several recommended HTTP security headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, and Permissions-Policy. The absence of these headers increases exposure to clickjacking, MIME-sniffing, and cross-site scripting attacks in browser-based API consumers.',
    'medium',
    5.3,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    '/api/users',
    'GET',
    E'GET /api/users HTTP/1.1\nHost: api.petstore-example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwiaWF0IjoxNzEwMDAwMDAwfQ.SEED_TOKEN\nAccept: application/json',
    E'HTTP/1.1 200 OK\nContent-Type: application/json\nX-Request-Id: req_8f3a2d1c\n\n[{"id":1001,"name":"User A"},{"id":1002,"name":"User B"}]',
    '{
        "missing_headers": [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Permissions-Policy"
        ],
        "present_headers": ["Content-Type", "X-Request-Id"],
        "hsts_present": false,
        "csp_present": false
    }',
    'Add a security headers middleware that applies to all API responses. At minimum include: Strict-Transport-Security (max-age≥31536000; includeSubDomains), X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy appropriate for your API consumers, and Permissions-Policy. Use the secureheaders library or equivalent for your framework.',
    'accepted',
    'dev@apiguard.local',
    NOW() - INTERVAL '1 day 20 hours',
    'Risk accepted for current release cycle. Headers will be added via middleware in v3.2.0 (next sprint). Low exploitability for a pure JSON API without a browser frontend.',
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Finding 8: LOW — Server Version Exposed in Response Headers
(
    '20000000-0000-0000-0000-000000000008',
    '10000000-0000-0000-0000-000000000001',
    'A8',
    'Security Misconfiguration',
    'a8_misconfiguration',
    'Server Version Exposed in Response Headers',
    'All API responses include the Server header with the full software version string (e.g., "nginx/1.24.0"). Exposing version information aids an attacker in identifying known CVEs applicable to the specific server version and reduces the effort required for targeted exploitation.',
    'low',
    3.1,
    'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    '/api/users',
    'GET',
    E'GET /api/users HTTP/1.1\nHost: api.petstore-example.com\nAccept: application/json',
    E'HTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: application/json\n\n[{"id":1001,"name":"User A"}]',
    '{
        "exposed_header": "Server",
        "exposed_value": "nginx/1.24.0",
        "software": "nginx",
        "version": "1.24.0",
        "known_cves_for_version": ["CVE-2023-44487"]
    }',
    'Configure the web server to suppress or genericize the Server header. For nginx, set "server_tokens off;" in nginx.conf. For other servers, consult the documentation for header suppression. Additionally, ensure the X-Powered-By header is removed if present.',
    'open',
    NULL,
    NULL,
    NULL,
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
)

ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 4. API INVENTORY
-- -----------------------------------------------------------------------------

INSERT INTO api_inventory (
    id,
    target_url,
    spec_hash,
    api_version,
    first_seen_at,
    last_scanned_at,
    scan_count
) VALUES
(
    '30000000-0000-0000-0000-000000000001',
    'https://api.petstore-example.com',
    'a3f1c2d4e5b6789012345678901234567890abcdef1234567890abcdef123456',
    '3.1.0',
    NOW() - INTERVAL '14 days',
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes',
    3
),
(
    '30000000-0000-0000-0000-000000000002',
    'https://legacy.inventory-api.internal',
    'b7e2d3f4a5c6890123456789012345678901bcdef2345678901bcdef234567',
    '1.4.2',
    NOW() - INTERVAL '60 days',
    NOW() - INTERVAL '1 day' + INTERVAL '30 minutes',
    7
)
ON CONFLICT (target_url) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 5. AUDIT LOG (10 entries, forward-chained SHA-256 hashes)
-- -----------------------------------------------------------------------------
-- Hashes are pre-computed placeholders representing a realistic chain.
-- Each prev_hash matches the chain_hash of the preceding row.
-- Entry 1 has prev_hash = NULL (genesis entry).
--
-- NOTE: audit_log has no-update / no-delete rules applied via CREATE RULE.
-- These rules use DO INSTEAD NOTHING which means ON CONFLICT clauses on INSERT
-- still work normally. The INSERT ... ON CONFLICT DO NOTHING below is safe.

INSERT INTO audit_log (
    id,
    actor_id,
    actor_type,
    action,
    resource_type,
    resource_id,
    ip_address,
    user_agent,
    before_state,
    after_state,
    metadata,
    prev_hash,
    chain_hash,
    created_at
) VALUES

-- Entry 1: Spec uploaded (genesis — no prev_hash)
(
    '40000000-0000-0000-0000-000000000001',
    'user:dev-01',
    'user',
    'spec_uploaded',
    'api_specs',
    '00000000-0000-0000-0000-000000000001',
    '192.168.1.101',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
    NULL,
    '{"spec_format":"openapi3","title":"Petstore E-Commerce API","version":"3.1.0","endpoint_count":24}',
    '{"source":"web_ui","file_size_bytes":18432,"content_type":"application/json"}',
    NULL,
    'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
    NOW() - INTERVAL '7 days'
),

-- Entry 2: Spec parsed
(
    '40000000-0000-0000-0000-000000000002',
    'system',
    'system',
    'spec_parsed',
    'api_specs',
    '00000000-0000-0000-0000-000000000001',
    NULL,
    'APIGuard/1.0 (parser-worker)',
    NULL,
    '{"parsed_endpoint_count":24,"auth_schemes":["bearerAuth","apiKeyAuth"],"parse_duration_ms":142}',
    '{"parser_version":"1.3.0","warnings":[],"ir_version":"2"}',
    'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
    'b2c3d4e5f6a7890123456789012345678901bcdef2345678901bcdef2345678',
    NOW() - INTERVAL '7 days' + INTERVAL '2 seconds'
),

-- Entry 3: Scan created (for completed scan)
(
    '40000000-0000-0000-0000-000000000003',
    'user:dev-01',
    'user',
    'scan_created',
    'scans',
    '10000000-0000-0000-0000-000000000001',
    '192.168.1.101',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
    NULL,
    '{"status":"pending","target_url":"https://api.petstore-example.com","modules":["a1_bola","a2_auth","a3_mass_assignment","a4_rate_limit","a5_function_auth","a8_misconfiguration"]}',
    '{"initiated_via":"web_ui","spec_id":"00000000-0000-0000-0000-000000000001"}',
    'b2c3d4e5f6a7890123456789012345678901bcdef2345678901bcdef2345678',
    'c3d4e5f6a7b8901234567890123456789012cdef3456789012cdef34567890',
    NOW() - INTERVAL '2 days'
),

-- Entry 4: Scan started
(
    '40000000-0000-0000-0000-000000000004',
    'system',
    'system',
    'scan_started',
    'scans',
    '10000000-0000-0000-0000-000000000001',
    NULL,
    'APIGuard/1.0 (scan-worker)',
    '{"status":"pending"}',
    '{"status":"running","started_at":"2024-03-08T13:00:00Z"}',
    '{"worker_id":"worker-03","queue_wait_ms":823}',
    'c3d4e5f6a7b8901234567890123456789012cdef3456789012cdef34567890',
    'd4e5f6a7b8c9012345678901234567890123def4567890123def456789012',
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour'
),

-- Entry 5: Scan completed
(
    '40000000-0000-0000-0000-000000000005',
    'system',
    'system',
    'scan_completed',
    'scans',
    '10000000-0000-0000-0000-000000000001',
    NULL,
    'APIGuard/1.0 (scan-worker)',
    '{"status":"running"}',
    '{"status":"completed","total_findings":8,"critical_count":2,"high_count":3,"medium_count":2,"low_count":1,"duration_seconds":1380}',
    '{"worker_id":"worker-03","endpoints_tested":24,"requests_made":1847}',
    'd4e5f6a7b8c9012345678901234567890123def4567890123def456789012',
    'e5f6a7b8c9d0123456789012345678901234ef5678901234ef56789012345',
    NOW() - INTERVAL '2 days' + INTERVAL '1 hour 23 minutes'
),

-- Entry 6: Finding triaged (BOLA confirmed)
(
    '40000000-0000-0000-0000-000000000006',
    'user:dev-01',
    'user',
    'finding_triaged',
    'findings',
    '20000000-0000-0000-0000-000000000001',
    '192.168.1.101',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
    '{"status":"open"}',
    '{"status":"confirmed","triaged_by":"dev@apiguard.local","triage_note":"Confirmed exploitable. Affects all /api/users/{id} variants. Ticket filed: SEC-101."}',
    '{"scan_id":"10000000-0000-0000-0000-000000000001","severity":"critical","owasp_id":"A1"}',
    'e5f6a7b8c9d0123456789012345678901234ef5678901234ef56789012345',
    'f6a7b8c9d0e1234567890123456789012345f6789012345f678901234567',
    NOW() - INTERVAL '1 day 22 hours'
),

-- Entry 7: Finding triaged (security headers accepted)
(
    '40000000-0000-0000-0000-000000000007',
    'user:dev-01',
    'user',
    'finding_triaged',
    'findings',
    '20000000-0000-0000-0000-000000000007',
    '192.168.1.101',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
    '{"status":"open"}',
    '{"status":"accepted","triaged_by":"dev@apiguard.local","triage_note":"Risk accepted for current release cycle. Headers will be added via middleware in v3.2.0."}',
    '{"scan_id":"10000000-0000-0000-0000-000000000001","severity":"medium","owasp_id":"A8"}',
    'f6a7b8c9d0e1234567890123456789012345f6789012345f678901234567',
    'a7b8c9d0e1f2345678901234567890123456a789012345a7890123456789',
    NOW() - INTERVAL '1 day 20 hours'
),

-- Entry 8: Report generated
(
    '40000000-0000-0000-0000-000000000008',
    'user:dev-01',
    'user',
    'report_generated',
    'scans',
    '10000000-0000-0000-0000-000000000001',
    '192.168.1.101',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
    NULL,
    '{"report_format":"json","findings_included":8,"generated_at":"2024-03-08T17:00:00Z"}',
    '{"report_id":"rpt_a1b2c3d4","file_size_bytes":24680,"download_url":"/api/reports/rpt_a1b2c3d4"}',
    'a7b8c9d0e1f2345678901234567890123456a789012345a7890123456789',
    'b8c9d0e1f2a3456789012345678901234567b890123456b8901234567890',
    NOW() - INTERVAL '1 day 19 hours'
),

-- Entry 9: Scan created (for failed scan)
(
    '40000000-0000-0000-0000-000000000009',
    'user:dev-01',
    'user',
    'scan_created',
    'scans',
    '10000000-0000-0000-0000-000000000003',
    '192.168.1.101',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
    NULL,
    '{"status":"pending","target_url":"https://legacy.inventory-api.internal","modules":["a1_bola","a2_auth","a5_function_auth"]}',
    '{"initiated_via":"web_ui","spec_id":"00000000-0000-0000-0000-000000000002"}',
    'b8c9d0e1f2a3456789012345678901234567b890123456b8901234567890',
    'c9d0e1f2a3b4567890123456789012345678c901234567c901234567890',
    NOW() - INTERVAL '1 day'
),

-- Entry 10: Scan failed
(
    '40000000-0000-0000-0000-000000000010',
    'system',
    'system',
    'scan_failed',
    'scans',
    '10000000-0000-0000-0000-000000000003',
    NULL,
    'APIGuard/1.0 (scan-worker)',
    '{"status":"running"}',
    '{"status":"failed","error_message":"connection refused: dial tcp legacy.inventory-api.internal:443: connect: connection refused"}',
    '{"worker_id":"worker-01","failure_stage":"connectivity_check","retry_attempts":3}',
    'c9d0e1f2a3b4567890123456789012345678c901234567c901234567890',
    'd0e1f2a3b4c5678901234567890123456789d012345678d0123456789012',
    NOW() - INTERVAL '1 day' + INTERVAL '30 minutes'
)

ON CONFLICT (id) DO NOTHING;

COMMIT;
