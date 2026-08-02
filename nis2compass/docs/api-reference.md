# NIS2 Compass — API Reference

**Base URL:** `http://<host>:8090`
**API prefix:** `/api/v1`
**Authentication:** Bearer JWT — include the token in the `Authorization` header on all protected endpoints:

```
Authorization: Bearer <token>
```

Tokens are obtained via `POST /api/v1/auth/token` and carry a finite expiry. All timestamps are ISO 8601 / RFC 3339 in UTC. The `GET /openapi.json` and `GET /docs` endpoints are public and do not require authentication.

---

## Table of Contents

1. [Health](#health)
2. [Authentication](#authentication)
3. [Organisations](#organisations)
4. [Assessments](#assessments)
5. [Reports](#reports)
6. [Controls](#controls)
7. [Artifacts](#artifacts)
8. [Audit Log](#audit-log)
9. [Control Templates](#control-templates)
10. [API Key Management](#api-key-management)
11. [API Schema](#api-schema)
12. [Error Responses](#error-responses)
13. [Pagination](#pagination)
14. [Rate Limiting](#rate-limiting)

---

## Health

### GET /health

Liveness check. No authentication required. Returns the running version of the API.

**Auth required:** No

**Response — 200 OK**

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

---

## Authentication

### POST /api/v1/auth/token

Exchange an API key for a short-lived JWT. The returned token must be supplied as a Bearer credential on all subsequent requests.

**Auth required:** No

**Request body**

```json
{
  "api_key": "nis2_apk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `api_key` | string | Yes | Issued API key for the service account or user |

**Response — 200 OK**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Status codes**

| Code | Condition |
|---|---|
| 200 | Token issued successfully |
| 401 | API key not recognised or revoked |
| 429 | Rate limit exceeded — see `Retry-After` response header |

---

## Organisations

All organisation endpoints require a valid Bearer JWT.

### GET /api/v1/organisations

List all registered organisations. Results are paginated.

**Auth required:** Yes

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | integer | 1 | Page number (1-based) |
| `per_page` | integer | 20 | Results per page (max 100) |

**Response — 200 OK**

```json
[
  {
    "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60001",
    "name": "Acme Energy GmbH",
    "industry": "energy",
    "country": "DE",
    "size": "large",
    "entity_type": "essential",
    "registration_number": "HRB-654321-B",
    "contact_email": "compliance@acme-energy.example.com",
    "created_at": "2026-01-10T09:00:00Z",
    "updated_at": "2026-01-10T09:00:00Z"
  }
]
```

Response includes `X-Total-Count` header with the total number of organisations.

---

### POST /api/v1/organisations

Create a new organisation. The `name` must be unique.

**Auth required:** Yes

**Request body**

```json
{
  "name": "Acme Energy GmbH",
  "industry": "energy",
  "country": "DE",
  "size": "large",
  "entity_type": "essential",
  "registration_number": "HRB-654321-B",
  "contact_email": "compliance@acme-energy.example.com"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Legal name of the organisation |
| `industry` | string | Yes | NIS2 sector (e.g., `energy`, `transport`, `banking`, `health`, `digital_infra`) |
| `country` | string | Yes | ISO 3166-1 alpha-2 country code |
| `size` | string | Yes | One of: `micro`, `small`, `medium`, `large` |
| `entity_type` | string | Yes | One of: `essential`, `important` |
| `registration_number` | string | No | Company registration number |
| `contact_email` | string | No | Primary compliance contact email address |

**Response — 201 Created**

Returns the created organisation object (same schema as GET response).

**Status codes**

| Code | Condition |
|---|---|
| 201 | Organisation created |
| 400 | Request body fails validation |
| 409 | An organisation with the same name already exists |

---

### GET /api/v1/organisations/{id}

Retrieve a single organisation by its UUID.

**Auth required:** Yes

**Path parameters**

| Parameter | Description |
|---|---|
| `id` | UUID of the organisation |

**Response — 200 OK**

Returns a single organisation object.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Organisation found |
| 404 | No organisation exists with the given id |

---

### PATCH /api/v1/organisations/{id}

Update one or more fields on an existing organisation. Only fields present in the request body are modified; omitted fields retain their current values.

**Auth required:** Yes

**Request body** (all fields optional)

```json
{
  "name": "Acme Energy AG",
  "contact_email": "new-compliance@acme-energy.example.com",
  "entity_type": "essential"
}
```

**Response — 200 OK**

Returns the full updated organisation object.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Organisation updated |
| 400 | Request body fails validation |
| 404 | No organisation exists with the given id |

---

### DELETE /api/v1/organisations/{id}

Delete an organisation. This operation cascades: all assessments, controls, and artifacts associated with the organisation are permanently deleted.

**Auth required:** Yes

**Response — 204 No Content**

Empty body.

**Status codes**

| Code | Condition |
|---|---|
| 204 | Organisation and all cascaded records deleted |
| 404 | No organisation exists with the given id |

---

## Assessments

### GET /api/v1/organisations/{org_id}/assessments

List all assessments belonging to a specific organisation.

**Auth required:** Yes

**Path parameters**

| Parameter | Description |
|---|---|
| `org_id` | UUID of the organisation |

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | — | Filter by assessment status: `draft`, `in_progress`, `under_review`, `completed`, `archived` |
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |

**Response — 200 OK**

```json
[
  {
    "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60002",
    "org_id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60001",
    "title": "NIS2 Article 21 Initial Assessment 2026",
    "status": "draft",
    "framework_version": "NIS2-2022/0383",
    "scope": "All network and information systems in scope of NIS2 for the DE energy sector",
    "assessor": "j.smith@acme-energy.example.com",
    "due_date": "2026-06-30",
    "completed_at": null,
    "created_at": "2026-01-15T10:00:00Z",
    "updated_at": "2026-01-15T10:00:00Z"
  }
]
```

Response includes `X-Total-Count` header.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Success |
| 404 | No organisation exists with the given org_id |

---

### POST /api/v1/organisations/{org_id}/assessments

Create a new assessment for an organisation. On creation, the API automatically inserts 10 control entries — one for each NIS2 Article 21(2) measure (a through j) — all set to `not_assessed` status.

**Auth required:** Yes

**Request body**

```json
{
  "title": "NIS2 Article 21 Initial Assessment 2026",
  "framework_version": "NIS2-2022/0383",
  "scope": "All network and information systems in scope of NIS2 for the DE energy sector",
  "assessor": "j.smith@acme-energy.example.com",
  "due_date": "2026-06-30"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | string | Yes | Human-readable assessment title |
| `framework_version` | string | No | Framework version identifier; defaults to `NIS2-2022/0383` |
| `scope` | string | No | Free-text description of the systems and services in scope |
| `assessor` | string | No | Name or email of the lead assessor |
| `due_date` | string (date) | No | Target completion date in `YYYY-MM-DD` format |

**Response — 201 Created**

Returns the created assessment object. The 10 control entries are accessible via `GET /api/v1/assessments/{id}/controls`.

**Status codes**

| Code | Condition |
|---|---|
| 201 | Assessment and 10 controls created |
| 400 | Request body fails validation |
| 404 | No organisation exists with the given org_id |

---

### GET /api/v1/assessments/{id}

Retrieve a single assessment by its UUID. The response includes a `summary` object with aggregated control status counts and the overall risk score.

**Auth required:** Yes

**Response — 200 OK**

```json
{
  "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60002",
  "org_id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60001",
  "title": "NIS2 Article 21 Initial Assessment 2026",
  "status": "in_progress",
  "framework_version": "NIS2-2022/0383",
  "scope": "All network and information systems in scope of NIS2 for the DE energy sector",
  "assessor": "j.smith@acme-energy.example.com",
  "due_date": "2026-06-30",
  "completed_at": null,
  "created_at": "2026-01-15T10:00:00Z",
  "updated_at": "2026-02-01T14:32:00Z",
  "summary": {
    "total_controls": 10,
    "compliant": 3,
    "partially_compliant": 4,
    "non_compliant": 2,
    "not_assessed": 1,
    "not_applicable": 0,
    "overall_risk_score": 4.7
  }
}
```

The `overall_risk_score` is the arithmetic mean of all non-null `risk_score` values across the assessment's controls.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Assessment found |
| 404 | No assessment exists with the given id |

---

### PATCH /api/v1/assessments/{id}

Update assessment fields, including status transitions. Only fields present in the request body are modified.

**Auth required:** Yes

**Valid status transitions**

| From | To | Typical trigger |
|---|---|---|
| `draft` | `in_progress` | Assessor begins populating controls |
| `in_progress` | `draft` | Scope or assessor change requires restart |
| `in_progress` | `under_review` | Assessor submits for sign-off |
| `under_review` | `in_progress` | Reviewer returns for rework |
| `under_review` | `completed` | Reviewer approves; all controls assessed |
| `completed` | `archived` | Assessment cycle closes; record preserved |

Backwards transitions (e.g., `completed` to `in_progress`) are not permitted.

**Request body** (all fields optional)

```json
{
  "status": "in_progress",
  "assessor": "a.jones@acme-energy.example.com",
  "due_date": "2026-07-31",
  "scope": "Updated scope following architecture review"
}
```

**Response — 200 OK**

Returns the full updated assessment object including the `summary` block.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Assessment updated |
| 400 | Invalid field value or disallowed status transition |
| 404 | No assessment exists with the given id |

---

### DELETE /api/v1/assessments/{id}

Delete an assessment. All associated controls and artifacts are permanently deleted.

**Auth required:** Yes

**Response — 204 No Content**

**Status codes**

| Code | Condition |
|---|---|
| 204 | Assessment deleted |
| 404 | No assessment exists with the given id |

---

## Reports

### POST /api/v1/assessments/{id}/report

Generate a compliance report for a completed assessment. The report can be produced in PDF, JSON, or SARIF format. PDF reports are streamed as binary content; JSON and SARIF reports are returned as downloadable attachments.

This endpoint is rate-limited to **3 requests per minute per user** (independent of the global rate limit).

**Auth required:** Yes (minimum scope: `read`)

**Path parameters**

| Parameter | Description |
|---|---|
| `id` | UUID of the assessment |

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `pdf` | Report output format. One of: `pdf`, `json`, `sarif` |

**Response — 200 OK (format=pdf)**

Binary PDF content returned as an attachment.

| Header | Value |
|---|---|
| `Content-Type` | `application/pdf` |
| `Content-Disposition` | `attachment; filename="nis2-assessment-<id>.pdf"` |

**Response — 200 OK (format=json)**

JSON report returned as an attachment.

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Content-Disposition` | `attachment; filename="report-<id>.json"` |

**Response — 200 OK (format=sarif)**

SARIF report returned as an attachment.

| Header | Value |
|---|---|
| `Content-Type` | `application/sarif+json` |
| `Content-Disposition` | `attachment; filename="report-<id>.sarif"` |

**Status codes**

| Code | Condition |
|---|---|
| 200 | Report generated successfully |
| 400 | Invalid `format` value |
| 404 | Assessment or organisation not found |
| 429 | Per-user report rate limit exceeded |
| 500 | Report generation failed (server-side error) |

---

## Controls

Controls are automatically created when an assessment is created. They are updated — not created — through the PATCH endpoint.

### GET /api/v1/assessments/{id}/controls

List all 10 control entries for an assessment.

**Auth required:** Yes

**Query parameters**

| Parameter | Type | Description |
|---|---|---|
| `status` | string | Filter by control status: `not_assessed`, `compliant`, `partially_compliant`, `non_compliant`, `not_applicable` |
| `nist_category` | string | Filter by NIST CSF category: `identify`, `protect`, `detect`, `respond`, `recover` |
| `measure_ref` | string | Filter by measure letter: `a` through `j` |

**Response — 200 OK**

```json
[
  {
    "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60010",
    "assessment_id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60002",
    "article_ref": "Art.21(2)(a)",
    "measure_ref": "a",
    "nist_category": "identify",
    "title": "Risk Analysis & Information Security Policies",
    "description": "Organisations must establish and maintain documented policies...",
    "status": "partially_compliant",
    "evidence": {
      "policy_ref": "IS-POL-001",
      "last_reviewed": "2025-11-01",
      "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "gap_description": "Risk register exists but has not been reviewed in 18 months.",
    "remediation_plan": "Schedule quarterly risk review cycle; assign risk owner.",
    "remediation_due": "2026-04-30",
    "risk_score": 5.5,
    "notes": "Risk appetite statement approved at board level in 2024.",
    "assessed_by": "j.smith@acme-energy.example.com",
    "assessed_at": "2026-02-01T14:00:00Z",
    "created_at": "2026-01-15T10:00:00Z",
    "updated_at": "2026-02-01T14:00:00Z"
  }
]
```

---

### GET /api/v1/assessments/{id}/controls/{measure_ref}

Retrieve a single control entry by its measure reference letter (`a` through `j`).

**Auth required:** Yes

**Path parameters**

| Parameter | Description |
|---|---|
| `id` | UUID of the assessment |
| `measure_ref` | Single character: `a`, `b`, `c`, `d`, `e`, `f`, `g`, `h`, `i`, or `j` |

**Response — 200 OK**

Returns a single control object (same schema as the list response).

**Status codes**

| Code | Condition |
|---|---|
| 200 | Control found |
| 404 | Assessment not found, or no control with the given measure_ref exists |

---

### PATCH /api/v1/assessments/{id}/controls/{measure_ref}

Update the assessment findings for a single control. All fields in the request body are optional; omitted fields are left unchanged.

**Auth required:** Yes

**Request body**

```json
{
  "status": "partially_compliant",
  "evidence": {
    "policy_ref": "IS-POL-001",
    "last_reviewed": "2025-11-01",
    "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "gap_description": "Risk register exists but has not been reviewed in 18 months.",
  "remediation_plan": "Schedule quarterly risk review cycle; assign risk owner.",
  "remediation_due": "2026-04-30",
  "risk_score": 5.5,
  "notes": "Risk appetite statement approved at board level in 2024."
}
```

| Field | Type | Description |
|---|---|---|
| `status` | string | One of: `not_assessed`, `compliant`, `partially_compliant`, `non_compliant`, `not_applicable` |
| `evidence` | object (JSONB) | Arbitrary JSON object referencing policies, procedure IDs, or artifact content hashes |
| `gap_description` | string | Description of identified gaps; required when status is `partially_compliant` or `non_compliant` |
| `remediation_plan` | string | Planned actions to address identified gaps |
| `remediation_due` | string (date) | Target date for remediation completion (`YYYY-MM-DD`) |
| `risk_score` | number | Risk severity on a 0.0–10.0 scale, aligned with the CVSS scoring convention |
| `notes` | string | Free-text assessor notes |

**Response — 200 OK**

Returns the full updated control object.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Control updated |
| 400 | Invalid field value (e.g., `risk_score` out of range, unrecognised `status`) |
| 404 | Assessment or control not found |

---

## Artifacts

Artifacts are evidence files uploaded against an assessment or a specific control within it.

### GET /api/v1/assessments/{id}/artifacts

List all artifacts associated with an assessment.

**Auth required:** Yes

**Query parameters**

| Parameter | Type | Description |
|---|---|---|
| `control_id` | UUID | Filter artifacts linked to a specific control |
| `type` | string | Filter by artifact type: `policy`, `procedure`, `evidence`, `report`, `screenshot`, `log`, `certificate`, `contract` |

**Response — 200 OK**

```json
[
  {
    "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60020",
    "assessment_id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60002",
    "control_id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60010",
    "type": "policy",
    "filename": "IS-POL-001-Information-Security-Policy.pdf",
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size_bytes": 204800,
    "mime_type": "application/pdf",
    "description": "Information Security Policy v3.2 approved 2025-10-01",
    "created_by": "j.smith@acme-energy.example.com",
    "created_at": "2026-02-01T14:05:00Z"
  }
]
```

Response includes `X-Total-Count` header.

---

### POST /api/v1/assessments/{id}/artifacts

Upload an evidence artifact. The request must be submitted as `multipart/form-data`. The API computes a SHA-256 hash of the file content and stores it in the `hash` field; this hash can be referenced in control `evidence` JSONB objects for integrity linkage.

**Auth required:** Yes

**Form fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | binary | Yes | The file to upload. Maximum 20 MB. |
| `type` | string | Yes | One of: `policy`, `procedure`, `evidence`, `report`, `screenshot`, `log`, `certificate`, `contract` |
| `control_id` | UUID | No | UUID of the control this artifact directly supports |
| `description` | string | No | Human-readable description of the artifact |

**Response — 201 Created**

Returns the artifact metadata object (same schema as GET response).

**Status codes**

| Code | Condition |
|---|---|
| 201 | Artifact uploaded and metadata stored |
| 400 | Missing required field or invalid `type` |
| 413 | File exceeds the 20 MB size limit |

---

### GET /api/v1/artifacts/{id}

Retrieve the metadata record for a single artifact.

**Auth required:** Yes

**Response — 200 OK**

Returns a single artifact metadata object.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Artifact found |
| 404 | No artifact exists with the given id |

---

### DELETE /api/v1/artifacts/{id}

Delete the artifact metadata record. This operation removes the database record only; the underlying file in storage is not deleted.

**Auth required:** Yes

**Response — 204 No Content**

**Status codes**

| Code | Condition |
|---|---|
| 204 | Metadata record deleted |
| 404 | No artifact exists with the given id |

---

## Audit Log

The audit log is append-only and immutable. Entries cannot be modified or deleted. Every state-changing operation against assessments, controls, and organisations is automatically recorded.

### GET /api/v1/audit

List audit log entries with optional filtering.

**Auth required:** Yes

**Query parameters**

| Parameter | Type | Description |
|---|---|---|
| `actor` | string | Filter by the actor (user or service account) who performed the action |
| `action` | string | Filter by action name (e.g., `assessment_created`, `control_updated`) |
| `resource_type` | string | Filter by resource type (e.g., `assessment`, `control`, `organisation`) |
| `resource_id` | UUID | Filter by the UUID of the affected resource |
| `risk_class` | string | Filter by risk classification: `INFO`, `WARNING`, `CRITICAL` |
| `after` | ISO 8601 timestamp | Return only entries with `timestamp` strictly after this value. Useful for cursor-based SIEM polling. Example: `after=2026-03-25T12:00:00Z` |
| `page` | integer | Page number (default 1) |
| `per_page` | integer | Results per page (default 20) |

**Response — 200 OK**

```json
[
  {
    "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60030",
    "action": "control_updated",
    "actor": "j.smith@acme-energy.example.com",
    "resource_type": "control",
    "resource_id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60010",
    "risk_class": "INFO",
    "metadata": {
      "measure_ref": "a",
      "previous_status": "not_assessed",
      "new_status": "partially_compliant"
    },
    "object_fingerprint": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "prev_hash": "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656b7fcf3e",
    "chain_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "timestamp": "2026-02-01T14:00:05Z"
  }
]
```

Response includes `X-Total-Count` header.

---

### GET /api/v1/audit/{id}

Retrieve a single audit log entry.

**Auth required:** Yes

**Response — 200 OK**

Returns a single audit log entry object.

**Status codes**

| Code | Condition |
|---|---|
| 200 | Entry found |
| 404 | No audit entry exists with the given id |

---

## Control Templates

### GET /api/v1/control-templates

Retrieve the reference library of all 10 NIS2 Article 21(2) control templates. These are the canonical measure definitions used to seed new assessments and are not organisation-specific.

**Auth required:** Yes

**Response — 200 OK**

```json
[
  {
    "id": 1,
    "measure_ref": "a",
    "article_ref": "Art.21(2)(a)",
    "title": "Risk Analysis & Information Security Policies",
    "description": "Organisations must establish and maintain documented policies...",
    "nist_category": "identify",
    "guidance": "Align with ISO/IEC 27001 clause 6.1 for risk assessment methodology..."
  }
]
```

Returns all 10 templates in measure_ref order (a through j). This endpoint does not paginate.

---

## API Key Management

API keys are the credentials used to obtain short-lived JWTs via `POST /api/v1/auth/token`. All three endpoints require a valid Bearer JWT.

### GET /api/v1/api-keys

List all active API keys for the authenticated account. The plaintext key value is never returned; only metadata is included.

**Auth required:** Yes

**Response — 200 OK**

```json
[
  {
    "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60040",
    "label": "ci-pipeline-prod",
    "scope": "read_write",
    "is_active": true,
    "created_by": "j.smith@acme-energy.example.com",
    "created_at": "2026-01-20T09:00:00Z",
    "last_used_at": "2026-03-24T22:15:00Z"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Unique identifier for the API key |
| `label` | string \| null | Human-readable label assigned at creation |
| `scope` | string | One of: `read`, `read_write` |
| `is_active` | boolean | `true` if the key has not been revoked |
| `created_by` | string \| null | Actor who created the key |
| `created_at` | ISO 8601 timestamp | Creation time |
| `last_used_at` | ISO 8601 timestamp \| null | Time the key was last used to obtain a token; `null` if never used |

---

### POST /api/v1/api-keys

Create a new API key. The raw key value is returned **once** in the response and is never stored or retrievable again. Store it securely immediately after creation.

**Auth required:** Yes

**Request body**

```json
{
  "label": "ci-pipeline-prod",
  "scope": "read_write",
  "expires_in_days": 90
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `label` | string | No | Human-readable label to identify the key's purpose |
| `scope` | string | No | One of: `read`, `read_write`. Defaults to `read_write` |
| `expires_in_days` | integer | No | Number of days until the key expires (1-365). When omitted the key does not expire. |

**Response — 201 Created**

```json
{
  "id": "018e5a1b-7c3d-7000-a1b2-c3d4e5f60040",
  "label": "ci-pipeline-prod",
  "scope": "read_write",
  "is_active": true,
  "created_by": "j.smith@acme-energy.example.com",
  "created_at": "2026-01-20T09:00:00Z",
  "last_used_at": null,
  "key": "nis2_a3f1c2e4b5d6...",
  "warning": "This is the only time the plaintext key will be shown. Store it securely."
}
```

The response extends the standard key metadata object with two additional fields:

| Field | Type | Description |
|---|---|---|
| `key` | string | The plaintext API key. Begins with the prefix `nis2_`. **Shown once only — not recoverable.** |
| `warning` | string | Reminder that the plaintext key will not be shown again |

**Status codes**

| Code | Condition |
|---|---|
| 201 | API key created |
| 400 | `scope` is not one of the accepted values |

---

### DELETE /api/v1/api-keys/{key_id}

Revoke an API key. The key's `is_active` flag is set to `false` and it can no longer be used to obtain a JWT. This operation is recorded in the audit log with risk class `WARNING`.

**Auth required:** Yes

**Path parameters**

| Parameter | Description |
|---|---|
| `key_id` | UUID of the API key to revoke |

**Response — 204 No Content**

Empty body.

**Status codes**

| Code | Condition |
|---|---|
| 204 | API key revoked |
| 404 | No API key exists with the given key_id |

---

## API Schema

### GET /openapi.json

Returns the full OpenAPI 3.0.3 specification for the NIS2 Compass API as a JSON document. This endpoint is used by `GET /docs` to populate the Swagger UI.

**Auth required:** No

**Response — 200 OK**

Returns an `application/json` body containing the OpenAPI 3.0.3 object, including all path definitions, component schemas, and security scheme declarations.

```json
{
  "openapi": "3.0.3",
  "info": {
    "title": "NIS2 Compass API",
    "version": "1.0.0"
  },
  "paths": { "...": {} }
}
```

---

### GET /docs

Serves the interactive Swagger UI. The UI loads the specification from `GET /openapi.json` and allows direct in-browser exploration and testing of all API endpoints.

**Auth required:** No

**Response — 200 OK**

Returns an `text/html` page embedding Swagger UI (via the `swagger-ui-dist` CDN bundle). Open this URL in a browser to explore and test the API interactively.

---

## Error Responses

All error responses use a consistent JSON envelope.

**Error response body**

```json
{
  "error": "Human-readable description of the problem.",
  "code": "SNAKE_CASE_ERROR_CODE"
}
```

**Common error codes**

| Code | HTTP Status | Description |
|---|---|---|
| `INVALID_INPUT` | 400 | Request body or query parameter failed validation |
| `NOT_FOUND` | 404 | The requested resource does not exist |
| `UNAUTHORIZED` | 401 | No valid Bearer token was supplied |
| `FORBIDDEN` | 403 | The authenticated principal lacks permission for this operation |
| `CONFLICT` | 409 | The operation conflicts with existing data (e.g., duplicate organisation name) |
| `RATE_LIMITED` | 429 | Too many requests — slow down and retry after the interval in `Retry-After` |
| `INTERNAL_ERROR` | 500 | Unexpected server-side error |

---

## Pagination

All list endpoints support cursor-free page/offset pagination.

**Query parameters**

| Parameter | Default | Description |
|---|---|---|
| `page` | 1 | 1-based page index |
| `per_page` | 20 | Number of results per page; maximum value is 100 |

**Response headers**

| Header | Description |
|---|---|
| `X-Total-Count` | Total number of records matching the query, before pagination |

Clients should use `X-Total-Count` and `per_page` to calculate the total number of pages. There are no `Link` headers; clients manage page arithmetic directly.

---

## Rate Limiting

The API enforces a default limit of **100 requests per minute per IP address**. When this limit is exceeded the API returns a `429 Too Many Requests` response.

**429 response**

```json
{
  "error": "Rate limit exceeded. Please retry after the indicated interval.",
  "code": "RATE_LIMITED"
}
```

**Response headers on 429**

| Header | Description |
|---|---|
| `Retry-After` | Number of seconds to wait before retrying |

Rate limiting state is stored in Redis. If Redis is unavailable the limit is not enforced and requests pass through normally.
