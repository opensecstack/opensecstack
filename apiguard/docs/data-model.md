# APIGuard Data Model

---

## APIGuard IR (Intermediate Representation)

The Rust parser normalises every supported schema format — OpenAPI 3.x, Swagger 2.x, GraphQL — into a single typed IR. All downstream layers (TestGen, OWASP modules) consume the IR, never the raw schema.

### IR Structure

```rust
pub struct ApiSpec {
    pub info:      SpecInfo,
    pub endpoints: Vec<Endpoint>,
    pub auth:      Vec<AuthScheme>,
}

pub struct SpecInfo {
    pub title:       String,
    pub version:     String,
    pub description: Option<String>,
    pub base_url:    String,
}

pub struct Endpoint {
    pub path:         String,           // e.g. "/api/v1/users/{id}"
    pub method:       HttpMethod,       // GET | POST | PUT | PATCH | DELETE | ...
    pub operation_id: Option<String>,
    pub tags:         Vec<String>,
    pub parameters:   Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    pub responses:    Vec<Response>,
    pub auth_schemes: Vec<String>,      // references into ApiSpec.auth
    pub deprecated:   bool,
}

pub struct Parameter {
    pub name:      String,
    pub location:  ParamLocation,       // path | query | header | cookie
    pub required:  bool,
    pub schema:    JsonSchema,
}

pub struct RequestBody {
    pub required:    bool,
    pub content_type: String,
    pub schema:      JsonSchema,
}

pub struct Response {
    pub status_code:  u16,
    pub content_type: Option<String>,
    pub schema:       Option<JsonSchema>,
}

pub struct AuthScheme {
    pub scheme_id: String,
    pub kind:      AuthKind,            // ApiKey | Http | OAuth2 | OpenIdConnect
    pub location:  Option<ParamLocation>,
    pub name:      Option<String>,      // header/query param name for ApiKey
}
```

---

## Scan Record

PostgreSQL table: `scans`

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `spec_url` | TEXT | URL of the OpenAPI spec (if provided by URL) |
| `spec_path` | TEXT | Server-side path of uploaded spec file |
| `spec_hash` | TEXT | SHA-256 of the spec content |
| `target_url` | TEXT | Base URL of the scanned API |
| `status` | ENUM | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `modules` | TEXT[] | List of OWASP module IDs that were run |
| `total_findings` | INT | Total findings across all severities |
| `critical_count` | INT | CRITICAL findings count |
| `high_count` | INT | HIGH findings count |
| `medium_count` | INT | MEDIUM findings count |
| `low_count` | INT | LOW findings count |
| `info_count` | INT | INFO findings count |
| `error_message` | TEXT | Error detail if status=`failed` |
| `started_at` | TIMESTAMPTZ | When scanning began |
| `completed_at` | TIMESTAMPTZ | When scanning finished |
| `created_at` | TIMESTAMPTZ | Record creation time |
| `updated_at` | TIMESTAMPTZ | Last update time |

### Scan Status State Machine

```
pending ──────────────────────────────► cancelled
   │
   ▼
running ──────────────────────────────► cancelled
   │                    │
   ▼                    ▼
completed            failed
```

Transitions are one-way. A `completed` or `failed` scan cannot be restarted — create a new scan.

---

## Finding Record

PostgreSQL table: `findings`

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `scan_id` | UUID | Foreign key → `scans.id` |
| `owasp_id` | TEXT | OWASP API Top 10 category (e.g. `API1:2023`) |
| `module_id` | TEXT | Module that produced this finding (e.g. `a1_bola`) |
| `title` | TEXT | Short vulnerability title |
| `description` | TEXT | Full description |
| `severity` | ENUM | `critical`, `high`, `medium`, `low`, `info` |
| `cvss_score` | NUMERIC(4,1) | CVSS 3.1 score 0.0–10.0 |
| `cvss_vector` | TEXT | Full CVSS 3.1 vector string |
| `endpoint_path` | TEXT | Affected path (e.g. `/api/v1/users/{id}`) |
| `endpoint_method` | TEXT | HTTP method |
| `evidence` | JSONB | Request/response pair proving the finding |
| `remediation` | TEXT | Fix guidance |
| `status` | ENUM | `open`, `confirmed`, `false_positive`, `accepted`, `fixed` |
| `triaged_by` | TEXT | User who last updated the triage status |
| `triage_note` | TEXT | Optional triage commentary |
| `triaged_at` | TIMESTAMPTZ | When the finding was last triaged |
| `created_at` | TIMESTAMPTZ | When the finding was recorded |
| `updated_at` | TIMESTAMPTZ | Last update time |

### Evidence JSONB Structure

```json
{
  "request": {
    "method": "GET",
    "url": "https://api.example.com/api/v1/users/2",
    "headers": {"Authorization": "Bearer <token>"},
    "body": null
  },
  "response": {
    "status_code": 200,
    "headers": {"Content-Type": "application/json"},
    "body": "{...sensitive data...}",
    "duration_ms": 42
  },
  "note": "Human-readable explanation of why this is a finding"
}
```

---

## API Spec Record

PostgreSQL table: `api_specs`

Stores uploaded OpenAPI spec files so they can be re-used across multiple scans.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `filename` | TEXT | Original filename |
| `content_type` | TEXT | `application/json` or `application/yaml` |
| `spec_hash` | TEXT | SHA-256 of the file content |
| `file_path` | TEXT | Server-side storage path |
| `size_bytes` | BIGINT | File size |
| `created_at` | TIMESTAMPTZ | Upload time |

---

## Audit Log Record

PostgreSQL table: `audit_log`

Every API action is logged here. The chain provides tamper detection: each entry hashes its content plus the previous entry's hash.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `seq` | BIGINT | Monotonically increasing sequence number |
| `actor_id` | TEXT | User ID or API key ID |
| `actor_type` | TEXT | `user` or `api_key` |
| `action` | TEXT | Action performed (e.g. `scan.create`, `finding.triage`) |
| `resource_type` | TEXT | Resource type (e.g. `scan`, `finding`) |
| `resource_id` | TEXT | UUID of the affected resource |
| `ip_address` | TEXT | Client IP address |
| `user_agent` | TEXT | Client user agent |
| `metadata` | JSONB | Action-specific context |
| `prev_hash` | TEXT | SHA-256 of the previous log entry |
| `chain_hash` | TEXT | SHA-256 of this entry's content + `prev_hash` |
| `created_at` | TIMESTAMPTZ | Event timestamp |

---

## API Key Record

PostgreSQL table: `api_keys`

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `key_hash` | TEXT | SHA-256 of the plaintext key — never the key itself |
| `label` | TEXT | Human-readable name |
| `scope` | TEXT | Space-separated list of allowed scopes |
| `is_active` | BOOL | Whether the key is active |
| `created_by` | TEXT | User ID who created the key |
| `expires_at` | TIMESTAMPTZ | Expiry time (NULL = no expiry) |
| `last_used_at` | TIMESTAMPTZ | Last successful authentication |
| `created_at` | TIMESTAMPTZ | Creation time |

---

## SARIF Output Mapping

When `--format sarif` is used, findings map to SARIF 2.1.0 as follows:

| Finding Field | SARIF Field |
|--------------|-------------|
| `id` | `result.correlationGuid` |
| `owasp_id` + `module_id` | `result.ruleId` |
| `title` | `result.message.text` |
| `severity` | `result.level` (`critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`) |
| `endpoint_path` + `endpoint_method` | `result.locations[0].logicalLocations` |
| `cvss_score` | `result.properties.cvssScore` |
| `cvss_vector` | `result.properties.cvssVector` |
| `remediation` | `result.fixes[0].description.text` |

The SARIF output is compatible with GitHub Advanced Security's code scanning upload action.
