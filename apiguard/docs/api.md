# APIGuard REST API Reference

Base URL: `http://localhost:8080/api/v1`

All endpoints return JSON unless otherwise noted. Authenticated endpoints require a valid JWT token passed in the `Authorization` header as `Bearer <token>`.

---

## Table of Contents

- [Authentication](#authentication)
- [Health and Status](#health-and-status)
- [Scans](#scans) (including [scan approval](#post-apiv1scansidapprove))
- [Findings](#findings)
- [API Inventory](#api-inventory)

---

## Authentication

### POST /api/v1/auth/token

Obtain a JWT access token and refresh token.

**Auth required:** No

**Request body:**

```json
{
  "username": "admin",
  "password": "secret"
}
```

**Response (`200 OK`):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

| Status Code | Description                |
|-------------|----------------------------|
| 200         | Token issued successfully  |
| 401         | Invalid credentials        |
| 422         | Missing required fields    |

---

### POST /api/v1/auth/refresh

Refresh an expired access token using a valid refresh token.

**Auth required:** No

**Request body:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (`200 OK`):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

| Status Code | Description                  |
|-------------|------------------------------|
| 200         | Token refreshed successfully |
| 401         | Invalid or expired refresh token |

---

## Health and Status

### GET /api/v1/health

Returns the health status of the API server and its dependencies.

**Auth required:** No

**Response (`200 OK`):**

```json
{
  "status": "healthy",
  "timestamp": "2026-03-24T12:00:00Z",
  "checks": {
    "database": "up",
    "rust_engine": "up",
    "queue": "up"
  }
}
```

| Status Code | Description                        |
|-------------|------------------------------------|
| 200         | Service is healthy                 |
| 503         | One or more dependencies are down  |

---

### GET /api/v1/version

Returns build and version information.

**Auth required:** No

**Response (`200 OK`):**

```json
{
  "version": "0.1.0",
  "commit": "a1b2c3d",
  "build_date": "2026-03-20T08:30:00Z",
  "go_version": "go1.22.1",
  "rust_engine_version": "0.1.0"
}
```

| Status Code | Description          |
|-------------|----------------------|
| 200         | Version info returned |

---

## Scans

### POST /api/v1/scans

Create a new security scan. Provide either `spec_url` (a remote OpenAPI spec URL, validated against SSRF) or `spec_path` (a local file path, restricted to the server's temp directory).

**Auth required:** Yes

**Request body:**

```json
{
  "target": "https://api.example.com",
  "spec_url": "https://api.example.com/openapi.json",
  "spec_path": "",
  "modules": ["a1_bola", "a5_function_auth", "a3_mass_assignment", "a7_ssrf", "a2_auth"],
  "auth_type": "bearer",
  "auth_token": "target-api-token",
  "auth_header": ""
}
```

| Field          | Type     | Required | Description                                                  |
|----------------|----------|----------|----------------------------------------------------------------|
| `target`       | string   | Yes      | Base URL of the API under test                                 |
| `spec_url`     | string   | No*      | URL to an OpenAPI/Swagger spec                                  |
| `spec_path`    | string   | No*      | Local filesystem path to a spec file (must resolve under the server's temp directory) |
| `modules`      | string[] | No       | Security test modules to run (default: all)                    |
| `auth_type`    | string   | No       | Auth type for the target API (e.g. `bearer`)                    |
| `auth_token`   | string   | No       | Token or key value for the target API. Never persisted to the database. |
| `auth_header`  | string   | No       | Custom header name to carry the auth token/key                 |

\* Either `spec_url` or `spec_path` must be provided.

Note: the request body is a **flat** JSON object — there is no nested `auth` or `options` object, and there is no `inline_spec` field.

**Response (`202 Accepted`):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

The scan is created and launched asynchronously in the background; the response body only ever contains `id` and `status`. Poll `GET /api/v1/scans/:id` for target, modules, timestamps, and progress.

| Status Code | Description                                          |
|-------------|-------------------------------------------------------|
| 202         | Scan created and accepted (launched, or awaiting approval — see below) |
| 400         | Invalid request body, or invalid `target`/`spec_path` |
| 401         | Unauthorized                                           |
| 403         | Blocked by CITADEL MARSHAL governance decision (`REFUSE`/`HARD_STOP`) |
| 422         | `spec_url`/`spec_path` missing, or spec parsing failed |
| 413         | Request body exceeds 1 MB                              |

Scan `status` follows this lifecycle: `pending` → `running` → `completed` / `failed` / `cancelled`. When two-person approval is required (see below), the initial status is `pending_approval` instead of `pending`.

> **Two-person approval:** when the server is configured with `citadel.require_approval: true` (default: `false`), this endpoint does not launch the scan. It returns `202 Accepted` with `"status": "pending_approval"` instead, and a different authenticated user must call `POST /api/v1/scans/:id/approve` before the scan runs. See [Scan Approval](#post-apiv1scansidapprove) below.

---

### GET /api/v1/scans

List scans with optional filters and pagination.

**Auth required:** Yes

**Query parameters:**

| Parameter  | Type   | Default | Description                                       |
|------------|--------|---------|---------------------------------------------------|
| `page`     | int    | 1       | Page number                                        |
| `per_page` | int    | 20      | Results per page (max 100)                         |
| `status`   | string | —       | Filter by status: `pending`, `pending_approval`, `running`, `completed`, `failed`, `cancelled` |
| `since`    | string | —       | Filter scans created after this ISO 8601 timestamp |
| `until`    | string | —       | Filter scans created before this ISO 8601 timestamp |
| `sort`     | string | `created_at` | Sort field: `created_at`, `status`            |
| `order`    | string | `desc`  | Sort order: `asc` or `desc`                        |

**Response (`200 OK`):**

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "target_url": "https://api.example.com",
      "status": "completed",
      "modules": ["a1_bola", "a5_function_auth", "a3_mass_assignment"],
      "finding_counts": {
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 2,
        "info": 4
      },
      "created_at": "2026-03-24T12:05:00Z",
      "completed_at": "2026-03-24T12:08:42Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

| Status Code | Description    |
|-------------|----------------|
| 200         | Scans returned |
| 401         | Unauthorized   |

---

### GET /api/v1/scans/:id

Get details for a specific scan including status, progress, and summary.

**Auth required:** Yes

**Response (`200 OK`):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "target_url": "https://api.example.com",
  "spec_url": "https://api.example.com/openapi.json",
  "status": "running",
  "progress": {
    "percentage": 65,
    "current_module": "a3_mass_assignment",
    "endpoints_tested": 42,
    "endpoints_total": 64
  },
  "modules": ["a1_bola", "a5_function_auth", "a3_mass_assignment", "a7_ssrf", "a2_auth"],
  "finding_counts": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 2
  },
  "created_at": "2026-03-24T12:05:00Z",
  "started_at": "2026-03-24T12:05:02Z",
  "completed_at": null
}
```

| Status Code | Description    |
|-------------|----------------|
| 200         | Scan returned  |
| 401         | Unauthorized   |
| 404         | Scan not found |

---

### GET /api/v1/scans/:id/findings

Get findings for a specific scan with optional filters and pagination.

**Auth required:** Yes

**Query parameters:**

| Parameter  | Type   | Default | Description                                           |
|------------|--------|---------|-------------------------------------------------------|
| `page`     | int    | 1       | Page number                                            |
| `per_page` | int    | 20      | Results per page (max 100)                             |
| `severity` | string | —       | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `module`   | string | —       | Filter by module name                                  |
| `status`   | string | —       | Filter by status: `open`, `confirmed`, `false_positive`, `accepted` |

**Response (`200 OK`):**

```json
{
  "data": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "module": "a1_bola",
      "severity": "high",
      "title": "Broken Object Level Authorization on GET /users/:id",
      "description": "Accessing user resources with another user's ID returns data without authorization check.",
      "endpoint": "GET /users/{id}",
      "status": "open",
      "cvss_score": 7.5,
      "created_at": "2026-03-24T12:06:15Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

| Status Code | Description        |
|-------------|--------------------|
| 200         | Findings returned  |
| 401         | Unauthorized       |
| 404         | Scan not found     |

---

### GET /api/v1/scans/:id/report

Download a scan report in the specified format.

**Auth required:** Yes

**Query parameters:**

| Parameter | Type   | Default | Description                                   |
|-----------|--------|---------|-----------------------------------------------|
| `format`  | string | `json`  | Report format: `html`, `pdf`, `json`, `sarif` |

**Response:**

- `json` and `sarif` formats return `Content-Type: application/json`.
- `html` returns `Content-Type: text/html`.
- `pdf` returns `Content-Type: application/pdf`.

**Response (`200 OK`, format=json):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target_url": "https://api.example.com",
  "generated_at": "2026-03-24T12:10:00Z",
  "summary": {
    "total_findings": 15,
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 4,
    "endpoints_tested": 64,
    "duration_seconds": 222
  },
  "findings": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "module": "a1_bola",
      "severity": "high",
      "title": "Broken Object Level Authorization on GET /users/:id",
      "description": "...",
      "endpoint": "GET /users/{id}",
      "evidence": { "..." : "..." },
      "remediation": "Implement object-level authorization checks.",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    }
  ]
}
```

| Status Code | Description                  |
|-------------|------------------------------|
| 200         | Report returned              |
| 401         | Unauthorized                 |
| 404         | Scan not found               |
| 422         | Unsupported report format    |

---

### DELETE /api/v1/scans/:id

Delete a scan and all associated findings. Running scans are cancelled before deletion.

**Auth required:** Yes

**Response (`204 No Content`):**

No response body.

| Status Code | Description            |
|-------------|------------------------|
| 204         | Scan deleted           |
| 401         | Unauthorized           |
| 404         | Scan not found         |

---

### POST /api/v1/scans/:id/approve

Approve a scan that is awaiting two-person sign-off (only relevant when `citadel.require_approval` is enabled — see the note under `POST /api/v1/scans` above). The caller becomes the CITADEL Kerkese Verifier: their own sinauth identity and bearer token are submitted to CITADEL MARSHAL alongside the original requester's, satisfying Separation of Duties (CITADEL Gate 3 / NDS). On success, the scan launches.

**Auth required:** Yes — and the caller must be a **different** authenticated user than whoever created the scan.

**Response (`200 OK`):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

| Status Code | Description                                                                 |
|-------------|------------------------------------------------------------------------------|
| 200         | Approved; scan launched                                                     |
| 401         | Unauthorized                                                                 |
| 403         | Approver is the same identity as the requester (Separation of Duties), or CITADEL MARSHAL returned REFUSE/HARD_STOP |
| 404         | No pending approval found for this scan                                     |
| 409         | Approval was already decided, or concurrently decided by someone else       |
| 410         | Approval window expired (24h) or the server restarted since the scan was requested — create a new scan |

---

### POST /api/v1/scans/:id/reject

Decline a scan that is awaiting two-person sign-off. The scan never runs.

**Auth required:** Yes — and the caller must be a **different** authenticated user than whoever created the scan.

**Request body (optional):**

```json
{ "reason": "target is out of scope for this environment" }
```

**Response (`200 OK`):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "failed"
}
```

| Status Code | Description                                                            |
|-------------|--------------------------------------------------------------------------|
| 200         | Rejected                                                                  |
| 401         | Unauthorized                                                              |
| 403         | Rejector is the same identity as the requester (Separation of Duties)   |
| 404         | No pending approval found for this scan                                 |
| 409         | Approval was already decided, or concurrently decided by someone else   |

---

### GET /api/v1/scans/:id/approval

Get the current two-person approval state for a scan: who requested it, and — once decided — who approved or rejected it, when, and why.

**Auth required:** Yes

**Response (`200 OK`):**

```json
{
  "id": "8f14e45f-ceea-467e-a3a3-f1a9c8b3c2d1",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "requested_by": "a1b2c3d4-...-sinauth-uuid",
  "status": "pending",
  "decided_by": null,
  "decided_at": null,
  "decision_reason": null,
  "created_at": "2026-03-24T12:05:00Z",
  "updated_at": "2026-03-24T12:05:00Z"
}
```

`status` is one of `pending`, `approved`, `rejected`.

| Status Code | Description                     |
|-------------|----------------------------------|
| 200         | Approval record returned         |
| 401         | Unauthorized                     |
| 404         | No approval record for this scan |

---

## Findings

### GET /api/v1/findings

List all findings across scans with optional filters and pagination.

**Auth required:** Yes

**Query parameters:**

| Parameter  | Type   | Default      | Description                                           |
|------------|--------|--------------|-------------------------------------------------------|
| `page`     | int    | 1            | Page number                                            |
| `per_page` | int    | 20           | Results per page (max 100)                             |
| `severity` | string | —            | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `module`   | string | —            | Filter by module name                                  |
| `status`   | string | —            | Filter by status: `open`, `confirmed`, `false_positive`, `accepted` |
| `scan_id`  | string | —            | Filter by scan ID                                      |
| `sort`     | string | `created_at` | Sort field: `created_at`, `severity`, `cvss_score`     |
| `order`    | string | `desc`       | Sort order: `asc` or `desc`                            |

**Response (`200 OK`):**

```json
{
  "data": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "module": "a1_bola",
      "severity": "high",
      "title": "Broken Object Level Authorization on GET /users/:id",
      "description": "Accessing user resources with another user's ID returns data without authorization check.",
      "endpoint": "GET /users/{id}",
      "status": "open",
      "cvss_score": 7.5,
      "created_at": "2026-03-24T12:06:15Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

| Status Code | Description        |
|-------------|--------------------|
| 200         | Findings returned  |
| 401         | Unauthorized       |

---

### GET /api/v1/findings/:id

Get full details for a specific finding including evidence and CVSS breakdown.

**Auth required:** Yes

**Response (`200 OK`):**

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "module": "a1_bola",
  "severity": "high",
  "title": "Broken Object Level Authorization on GET /users/:id",
  "description": "Accessing user resources with another user's ID returns data without authorization check.",
  "endpoint": "GET /users/{id}",
  "status": "open",
  "evidence": {
    "request": {
      "method": "GET",
      "url": "https://api.example.com/users/42",
      "headers": {
        "Authorization": "Bearer <token_for_user_1>"
      }
    },
    "response": {
      "status_code": 200,
      "body": "{\"id\":42,\"email\":\"other@example.com\",\"name\":\"Other User\"}"
    },
    "notes": "Authenticated as user 1 but retrieved user 42's data."
  },
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
  "cvss_breakdown": {
    "attack_vector": "Network",
    "attack_complexity": "Low",
    "privileges_required": "Low",
    "user_interaction": "None",
    "scope": "Unchanged",
    "confidentiality": "High",
    "integrity": "None",
    "availability": "None"
  },
  "remediation": "Implement object-level authorization checks to ensure users can only access their own resources.",
  "references": [
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
  ],
  "created_at": "2026-03-24T12:06:15Z",
  "updated_at": "2026-03-24T12:06:15Z"
}
```

| Status Code | Description          |
|-------------|----------------------|
| 200         | Finding returned     |
| 401         | Unauthorized         |
| 404         | Finding not found    |

---

### PATCH /api/v1/findings/:id

Update the triage status of a finding.

**Auth required:** Yes

**Request body:**

```json
{
  "status": "false_positive",
  "comment": "This endpoint requires an admin role which was used during testing."
}
```

| Field     | Type   | Required | Description                                                  |
|-----------|--------|----------|--------------------------------------------------------------|
| `status`  | string | Yes      | New status: `confirmed`, `false_positive`, or `accepted`     |
| `comment` | string | No       | Reason for the status change                                 |

**Response (`200 OK`):**

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "false_positive",
  "comment": "This endpoint requires an admin role which was used during testing.",
  "updated_at": "2026-03-24T14:30:00Z"
}
```

| Status Code | Description              |
|-------------|--------------------------|
| 200         | Finding updated          |
| 400         | Invalid status value     |
| 401         | Unauthorized             |
| 404         | Finding not found        |

---

## API Inventory

### GET /api/v1/inventory

List all tracked APIs that have been scanned.

**Auth required:** Yes

**Query parameters:**

| Parameter  | Type   | Default      | Description                    |
|------------|--------|--------------|--------------------------------|
| `page`     | int    | 1            | Page number                    |
| `per_page` | int    | 20           | Results per page (max 100)     |
| `sort`     | string | `last_scan`  | Sort field: `last_scan`, `url` |
| `order`    | string | `desc`       | Sort order: `asc` or `desc`    |

**Response (`200 OK`):**

```json
{
  "data": [
    {
      "id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
      "url": "https://api.example.com",
      "spec_url": "https://api.example.com/openapi.json",
      "endpoint_count": 64,
      "total_scans": 12,
      "last_scan": "2026-03-24T12:05:00Z",
      "last_scan_status": "completed",
      "open_findings": {
        "critical": 0,
        "high": 1,
        "medium": 3,
        "low": 2,
        "info": 4
      }
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

| Status Code | Description        |
|-------------|--------------------|
| 200         | Inventory returned |
| 401         | Unauthorized       |

---

### GET /api/v1/inventory/:id/history

Get the scan history for a specific tracked API.

**Auth required:** Yes

**Query parameters:**

| Parameter  | Type   | Default | Description                |
|------------|--------|---------|----------------------------|
| `page`     | int    | 1       | Page number                |
| `per_page` | int    | 20      | Results per page (max 100) |

**Response (`200 OK`):**

```json
{
  "api_id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
  "url": "https://api.example.com",
  "data": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "modules": ["a1_bola", "a5_function_auth", "a3_mass_assignment"],
      "finding_counts": {
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 2,
        "info": 4
      },
      "created_at": "2026-03-24T12:05:00Z",
      "completed_at": "2026-03-24T12:08:42Z",
      "duration_seconds": 222
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

| Status Code | Description        |
|-------------|--------------------|
| 200         | History returned   |
| 401         | Unauthorized       |
| 404         | API not found      |

---

## Common Error Response

All error responses follow a consistent structure:

```json
{
  "error": {
    "code": "not_found",
    "message": "Scan with ID 550e8400-e29b-41d4-a716-446655440000 not found."
  }
}
```

| Field     | Type   | Description                              |
|-----------|--------|------------------------------------------|
| `code`    | string | Machine-readable error code              |
| `message` | string | Human-readable error description        |

### Standard Error Codes

| HTTP Status | Code              | Description                          |
|-------------|-------------------|--------------------------------------|
| 400         | `bad_request`     | Malformed request body or parameters |
| 401         | `unauthorized`    | Missing or invalid auth token        |
| 404         | `not_found`       | Resource does not exist              |
| 422         | `validation_error`| Request failed validation            |
| 429         | `rate_limited`    | Too many requests                    |
| 500         | `internal_error`  | Unexpected server error              |

---

## Rate Limiting

The API enforces rate limits on all endpoints. Rate limit headers are included in every response:

| Header                  | Description                        |
|-------------------------|------------------------------------|
| `X-RateLimit-Limit`    | Maximum requests per window        |
| `X-RateLimit-Remaining`| Requests remaining in current window |
| `X-RateLimit-Reset`    | Unix timestamp when the window resets |

When the rate limit is exceeded, the API returns `429 Too Many Requests`.
