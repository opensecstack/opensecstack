<!--
Copyright 2024 The OpenSecStack Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# OpenSecStack API Overview

## Introduction

The OpenSecStack ecosystem exposes one REST API per service. Each API is independently versioned and self-contained. All APIs are documented with OpenAPI 3.x and share a common set of conventions described in this document.

## Service API Index

| Service | Base Path | Description |
|---|---|---|
| OpenCSIRT | `/api/v1` | CSIRT case and incident management |
| OpenScrub | `/api/v1` | Threat intelligence feed scrubbing and deduplication |
| ThreatFlow | `/api/v1` | Real-time threat event ingestion and routing |
| IRFlow | `/api/v1` | Incident response workflow automation |
| CyberPath | `/api/v1` | Attack path analysis and graph traversal |
| VertGuard | `/api/v1` | Vertical threat and vulnerability guard |
| NIS2Compass | `/api/v1` | NIS2 compliance tracking and reporting |
| APIGuard | `/api/v1` | API gateway security and policy enforcement |

Each service is reached at its own host or sub-path depending on the deployment topology. The base path is appended to the service's root URL (e.g., `https://threatflow.example.com/api/v1/events`).

## Authentication

All APIs use **JWT bearer tokens** for authentication. Tokens are issued per-service and are not interchangeable between services. Include the token in every request:

```
Authorization: Bearer <token>
```

Token expiry and refresh policies are configured per-service. Refer to each service's own documentation for token issuance endpoints.

## Common Conventions

All service APIs follow these conventions:

- **Format**: JSON request and response bodies (`Content-Type: application/json`).
- **Field naming**: `snake_case` for all JSON field names.
- **Timestamps**: RFC 3339 format (`2024-01-15T10:30:00Z`).
- **Identifiers**: UUIDs (v4) for all resource identifiers.
- **Pagination**: list endpoints accept `limit` (default 50, max 200) and `offset` query parameters and return a `total` count in the response body.
- **Errors**: error responses use a standard envelope: `{ "code": "...", "message": "...", "details": {} }`.
- **HTTP status codes**: standard semantics — 200 OK, 201 Created, 204 No Content, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 422 Unprocessable Entity, 500 Internal Server Error.

## Cross-Service Integration

When one OpenSecStack service calls another (e.g., IRFlow triggering a VertGuard scan), it uses a **service-to-service JWT** that is distinct from user-issued tokens. These internal tokens carry a `service` claim identifying the caller and are issued by each service's own token endpoint using a pre-shared client credential. User tokens must never be forwarded between services.

## OpenAPI Specifications

Each service ships its OpenAPI 3.x specification at:

```
<service-repo>/api/openapi.yaml
```

The spec is the authoritative reference for all request/response schemas, path parameters, and error codes. All specs can be imported into tools such as Swagger UI, Redoc, or Postman.

## Rate Limiting

All APIs enforce rate limiting via middleware applied at the router level. Limits are configurable per deployment. When a limit is exceeded the API returns `429 Too Many Requests` with a `Retry-After` header indicating when the client may retry.
