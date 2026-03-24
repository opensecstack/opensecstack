# OWASP API Top 10 Coverage Map

The definitive reference for what APIGuard tests, how it tests it, what it cannot detect, and what the known false positive scenarios are.

## Coverage Matrix

| ID | Vulnerability | What APIGuard Tests | Detection Method | Confidence | Known FPs | Cannot Detect |
|----|--------------|--------------------|--------------------|------------|-----------|---------------|
| A1 | BOLA (Broken Object Level Auth) | Access object IDs belonging to other users/tenants. Horizontal privilege escalation. | Enumerate IDs, vary auth tokens, compare responses for data leakage. | HIGH for REST. MEDIUM for GraphQL. | APIs returning identical 404 for auth vs not-found | Authorisation logic requiring business context (e.g. 'user is a manager of this department') |
| A2 | Broken Authentication | Missing auth on protected endpoints. Weak token validation. Token in URL. | Remove auth headers, use expired tokens, replay tokens, check URL params. | HIGH for missing auth. MEDIUM for weak validation. | Endpoints intentionally public that look protected by naming convention | Credential stuffing (requires real credential list). Session fixation. |
| A3 | Broken Object Property Level Auth | Mass assignment. Excessive data exposure. Write to fields that should be read-only. | Send extra fields in POST/PUT/PATCH. Compare response fields to schema. | MEDIUM — requires schema to define expected fields | Undocumented but intentional fields | Fields not in OpenAPI schema but legitimately writable |
| A4 | Unrestricted Resource Consumption | No rate limiting. Large payload acceptance. Expensive query parameters. | Send concurrent requests. Send large payloads. Use expensive filter params. | HIGH for absent rate limiting. LOW for DoS potential. | Dev environments without rate limits | Rate limits enforced at infrastructure layer not detectable via HTTP responses |
| A5 | Broken Function Level Auth | Vertical privilege escalation. Admin endpoints accessible to regular users. | Use lower-privilege token against admin-tagged endpoints. Test HTTP method variations. | MEDIUM — depends on schema tagging | Endpoints not tagged as admin in OpenAPI schema | Role hierarchies more complex than admin/user binary |
| A6 | Unrestricted Access to Sensitive Business Flows | Automated abuse of business flows. Bot-exploitable workflows. | Rapid-fire execution of sensitive endpoints. Detect absence of bot controls. | LOW — business context dependent | Any high-throughput legitimate API use case | CAPTCHA bypass. Real bot behaviour simulation. |
| A7 | Server Side Request Forgery (SSRF) | URL parameters that fetch remote resources. | Inject SSRF payloads into URL-type parameters. Check for out-of-band interactions. | MEDIUM — requires OAST/out-of-band detection | Parameters that accept URLs for legitimate external fetch | Blind SSRF without out-of-band detection configured |
| A8 | Security Misconfiguration | Missing security headers. Debug endpoints exposed. Verbose error messages. CORS misconfiguration. | Check response headers. Probe debug/health/docs endpoints. Trigger errors. | HIGH for headers. HIGH for debug endpoints. | APIs intentionally exposing verbose errors in dev | Configuration differences between environments not in scope |
| A9 | Improper Inventory Management | Undocumented endpoints. Old API versions still accessible. | Probe common version paths (/v1/, /v2/, /api/, /internal/). Compare to schema. | MEDIUM — probe-based discovery | Legitimate versioned APIs with older versions still intentionally active | Endpoints on subdomains or different base paths not in scope |
| A10 | Unsafe Consumption of APIs | Third-party API data passed unsanitised into responses. | Inject payloads via third-party data simulation. Check if reflected in response. | LOW — requires third-party simulation | Any API that legitimately reflects input | Complex injection chains through multiple hops |

## Module Status

| Module | Default | Notes |
|--------|---------|-------|
| `a1_bola` | Enabled | Requires at least 2 auth tokens for cross-user testing |
| `a2_auth` | Enabled | |
| `a3_mass_assignment` | Enabled | |
| `a4_rate_limiting` | Enabled | |
| `a5_function_auth` | Enabled | Best results when schema tags admin endpoints |
| `a6_business_flow` | **Disabled** | Requires manual configuration of sensitive endpoints |
| `a7_ssrf` | Enabled | Best with OAST/out-of-band detection configured |
| `a8_misconfig` | Enabled | |
| `a9_inventory` | Enabled | |
| `a10_unsafe_consumption` | **Disabled** | Requires OAST setup |

## Finding Severity Levels

| Severity | CVSS Range | CI/CD Default | Description |
|----------|-----------|---------------|-------------|
| CRITICAL | 9.0 – 10.0 | FAIL build | Immediate exploitation risk. RCE, auth bypass, mass data exposure. |
| HIGH | 7.0 – 8.9 | FAIL build | Significant risk. Direct data access, privilege escalation, SSRF. |
| MEDIUM | 4.0 – 6.9 | WARN (configurable) | Exploitable with conditions. Rate limit absence, verbose errors, CORS. |
| LOW | 0.1 – 3.9 | PASS | Minor issues. Informational leakage, missing non-critical headers. |
| INFO | 0.0 | PASS | Observations with no direct security impact. |
