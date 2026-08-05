# OpenAPI Parser Specification

## Supported Input Formats

| Format | Version | File Extensions | Notes |
|--------|---------|-----------------|-------|
| OpenAPI | 3.0.x | *.yaml, *.yml, *.json | Full support. Reference resolution ($ref) included. |
| OpenAPI | 3.1.x | *.yaml, *.yml, *.json | Full support. JSON Schema alignment handled. |
| Swagger | 2.0 | *.yaml, *.yml, *.json | Supported. Auto-converted to OpenAPI 3.x IR internally. |
| GraphQL | Any | *.graphql, *.gql | **Planned, not implemented** — no `graphql.rs` parser exists yet (matches README.md's own "GraphQL planned" note). |
| Postman Collection | 2.1 | *.json | Experimental. Converted to OpenAPI IR. Some features unsupported. |
| URL | — | https:// | Fetch from URL with configurable timeout and auth. |

## Parser Guarantees

- **Memory safe** — Rust parser cannot panic on malformed input. All errors are typed Results.
- **Deterministic** — Identical input always produces identical IR. No randomness in parsing.
- **Complete** — All `$ref` references resolved before IR is produced. No lazy resolution.
- **Validated** — IR is validated against APIGuard's internal schema before leaving the parser layer.
- **Bounded** — Parser enforces maximum schema size (configurable, default 10MB). Rejects circular refs beyond depth 10.

## APIGuard Internal Representation (IR)

The IR is the normalised form all downstream layers consume. It is a typed Rust struct serialised to JSON for the Go layer.

| IR Field | Type | Source | Description |
|----------|------|--------|-------------|
| `endpoints[]` | Array\<Endpoint\> | paths + methods | All API endpoints with method, path, parameters, request body, responses |
| `auth_schemes[]` | Array\<AuthScheme\> | securitySchemes | All defined auth methods: JWT, OAuth2, API key, basic, bearer |
| `endpoint.security[]` | Array\<string\> | endpoint security | Which auth schemes apply to this endpoint |
| `endpoint.parameters[]` | Array\<Parameter\> | parameters | Path, query, header, cookie params with type, required flag, schema |
| `endpoint.request_body` | RequestBody \| null | requestBody | Content types, schema, required flag |
| `endpoint.responses{}` | Map\<code, Response\> | responses | Expected response codes with schemas |
| `endpoint.tags[]` | Array\<string\> | tags | Used to identify admin/sensitive endpoints for A5 testing |
| `endpoint.x_apiguard{}` | Map\<string, any\> | x-apiguard extensions | APIGuard-specific hints: skip, custom severity, expected sensitive fields |
| `metadata.base_url` | string | servers[0].url | Primary target URL |
| `metadata.api_version` | string | info.version | API version for inventory tracking |
| `metadata.schema_hash` | string (SHA256) | computed | Fingerprint of input schema for change detection |

## Error Handling

The parser returns typed errors, never panics:

| Error Type | Cause | Recovery |
|-----------|-------|----------|
| `ParseError::InvalidFormat` | File is not valid YAML/JSON/GraphQL | Report to user with line number |
| `ParseError::UnsupportedVersion` | Schema version not supported | Suggest supported versions |
| `ParseError::CircularReference` | `$ref` cycle exceeds depth 10 | Report cycle path |
| `ParseError::SizeExceeded` | Schema exceeds max size | Suggest increasing `scanner.max_spec_size_mb` |
| `ParseError::InvalidSchema` | Schema is syntactically valid but semantically invalid | Report specific validation failures |
| `ParseError::FetchError` | URL schema could not be fetched | Report HTTP status or network error |
