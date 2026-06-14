---
id: 02-api-attack-defence
order: 2
duration_minutes: 90
---

# Lesson 2: API Attack and Defence with APIGuard

## Exploiting BOLA: the anatomy of an object-level authorization failure

Broken Object Level Authorization (BOLA) is the most prevalent API vulnerability class because it arises from a systematic omission rather than an implementation error: the developer implemented an endpoint but forgot that the object identifier in the request is attacker-controlled. Consider a REST endpoint that retrieves a user's order:

```text
GET /api/v1/orders/8472
Authorization: Bearer <token>
```

The token identifies the calling user as `alice`. The order with ID `8472` belongs to `alice`. The server returns the order details. Now consider:

```text
GET /api/v1/orders/8473
Authorization: Bearer <token>
```

If the server returns the order details for ID `8473` — which belongs to `bob` — without checking that `alice` has access to `bob`'s orders, this is BOLA. The fix is an authorization check at the data layer: before returning any object, verify that the authenticated principal is authorised to access that specific object instance. Declarative authorization frameworks (OPA, Casbin, Spring Security method-level authorization) make this pattern enforceable at the framework level rather than requiring per-endpoint developer discipline.

## Authentication and token security

API authentication failures cluster around three patterns. First, missing authentication: an endpoint that should be protected is accessible without a token, typically because a developer added an endpoint after the authentication middleware was configured, or because the endpoint was intended as "internal only" but is reachable from the internet. Second, weak token validation: the API accepts tokens signed with `none` algorithm (a classic JWT vulnerability), or does not validate expiry, or accepts tokens signed with a key that is weak or leaked. Third, token leakage: the API echoes tokens back in response bodies, includes them in log output, or exposes them in HTTP redirects.

```python
# Weak: accepting alg:none in JWT validation
import jwt
# This is WRONG — allows any claim to be forged
decoded = jwt.decode(token, options={"verify_signature": False})

# Correct: enforce algorithm and validate against your key
decoded = jwt.decode(
    token,
    key=PUBLIC_KEY,
    algorithms=["RS256"],   # explicit allowlist, never "none"
    options={"require": ["exp", "iss", "sub"]},
)
```

Rate limiting on authentication endpoints is non-negotiable. Without it, credential stuffing attacks — automated login attempts using breach-sourced credential lists — are trivially executable against any API with a login endpoint. The defence is a combination of rate limiting per IP and per account, CAPTCHA for human verification, and account lockout with exponential backoff.

## Input validation and injection in APIs

APIs that accept structured input (JSON, XML, form data) must validate every field against a strict schema before processing. The most common injection classes in APIs are:

- **NoSQL injection**: input fields passed directly into MongoDB query objects without sanitisation can modify the query structure. `{"username": {"$gt": ""}}` passed as a username field may match all users in a MongoDB collection.
- **GraphQL injection and introspection abuse**: GraphQL APIs that enable introspection in production expose the full schema to attackers. Combined with query depth and complexity limits being absent, this enables deeply nested queries that exhaust server resources.
- **SSRF via URL parameters**: any API that accepts a URL and fetches it server-side must whitelist destinations. A vulnerable endpoint that fetches `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns AWS instance credentials.

```python
# Vulnerable: constructing a MongoDB query from user input
def get_user(username: str):
    return db.users.find_one({"username": username})

# Correct: validate type and structure first
def get_user(username: str):
    if not isinstance(username, str) or len(username) > 64:
        raise ValueError("Invalid username")
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        raise ValueError("Username contains disallowed characters")
    return db.users.find_one({"username": username})
```

## Running APIGuard: interpreting a scan report

APIGuard operates in three modes: passive analysis (reading an OpenAPI specification or recorded traffic), active scanning (sending live probes against a running API), and authenticated scanning (using a provided credential to test authorised endpoints). For the lab exercise, you will run an authenticated active scan against the target API.

```bash
# Authenticate and run an active scan
apiguard scan \
  --target https://lab-api.cyberpath.local \
  --auth-header "Authorization: Bearer $LAB_TOKEN" \
  --spec /lab/openapi.yaml \
  --output /lab/report.json \
  --output-format json

# Generate a human-readable summary
apiguard report summarise /lab/report.json
```

The report JSON structure groups findings by OWASP API Top 10 category, assigns a severity (Critical, High, Medium, Low, Informational), and provides for each finding: the affected endpoint, the HTTP request that triggered the finding, the expected vs. actual response, and remediation guidance.

```json
{
  "summary": {
    "total_findings": 14,
    "critical": 2,
    "high": 5,
    "medium": 4,
    "low": 3
  },
  "findings": [
    {
      "id": "FIND-001",
      "category": "API1:2023",
      "title": "BOLA on /api/v1/accounts/{id}",
      "severity": "Critical",
      "endpoint": "GET /api/v1/accounts/{id}",
      "evidence": {
        "request": "GET /api/v1/accounts/102 HTTP/1.1\nAuthorization: Bearer <user-A-token>",
        "response_status": 200,
        "expected_status": 403
      },
      "remediation": "Add object-level authorization check before returning account data."
    }
  ]
}
```

## Remediation patterns and secure defaults

Remediating API security findings follows a set of well-established patterns. For BOLA: implement resource-based access control at the data layer. For authentication failures: audit all endpoints against your authentication middleware configuration; use automated tests that verify 401 responses on protected endpoints when no token is supplied. For mass assignment (BOPLA): use explicit allow-listing of writable fields rather than passing the full request body to your ORM. For rate limiting: implement limits at the API gateway layer (nginx-based, cloud-provider API gateway, or a dedicated solution like Tyk or Kong) rather than application code.

The most valuable long-term defence is API design review before implementation: threat modelling each endpoint against the OWASP API Top 10 during design, not after deployment. APIGuard supports this via its specification analysis mode — running a scan against an OpenAPI YAML before the API is even built surfaces BOLA risks (endpoints with user-controlled identifiers and no documented authorization scheme), missing authentication annotations, and SSRF-prone URL parameters.
