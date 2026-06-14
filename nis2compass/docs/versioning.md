# NIS2 Compass — Versioning & Backwards Compatibility Policy

This document defines how NIS2 Compass versions its REST API, database schema,
and SDK surface, and what guarantees consumers can rely on between releases.

---

## Semantic Versioning

NIS2 Compass follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (X.0.0) — Breaking changes to the REST API or data model
- **MINOR** (1.X.0) — New features, new endpoints, new optional fields (backwards compatible)
- **PATCH** (1.0.X) — Bug fixes, security patches, documentation updates (backwards compatible)

The version is exposed at runtime via `GET /health` (`"version": "1.0.0"`) and
in the OpenAPI specification served by `GET /openapi.json`.

---

## API Stability Guarantee

Starting with v1.0.0, NIS2 Compass commits to the following contract.

### What We Will NOT Break (Without a Major Version Bump)

- Existing REST endpoint paths (e.g., `/api/v1/organisations`, `/api/v1/assessments/{id}/controls/{measure_ref}`)
- Existing request field names and types
- Existing response field names and types
- HTTP status codes for existing success and error scenarios
- Error response envelope structure (`error` + `code` fields)
- Authentication mechanisms (JWT via `POST /api/v1/auth/token`, API key creation and revocation)
- Pagination contract (`page` / `per_page` query parameters, `X-Total-Count` response header)
- Audit log chain-hash algorithm (SHA-256) and the `chain_hash` / `prev_hash` fields
- Artifact integrity hashing algorithm (SHA-256)

### What We MAY Change in Minor Versions

- Add new optional request fields (existing requests continue to work)
- Add new response fields (clients should ignore unknown fields)
- Add new API endpoints
- Add new enum values (e.g., new control statuses, new artifact types, new risk classes)
- Add new query parameters for filtering or pagination
- Improve error messages (human-readable `error` text may change; `code` values stay the same)
- Add new report formats to `POST /api/v1/assessments/{id}/report`
- Add new NIST CSF category mappings to control templates
- Increase the default or maximum `per_page` limit

### What Requires a Major Version Bump

- Removing or renaming an endpoint
- Removing or renaming a request or response field
- Changing a field's type (e.g., string to integer, UUID to integer)
- Changing authentication requirements or token format
- Changing the audit chain-hash algorithm
- Removing an enum value (e.g., dropping a control status)
- Changing default pagination behaviour in a way that breaks existing clients
- Altering the assessment status-transition state machine in a backwards-incompatible way
- Changing the error response envelope structure

---

## Deprecation Policy

Before removing any feature in a major version:

1. **Announce deprecation** in a minor release (at least one minor version before removal).
2. **Add a `Deprecation` header** to affected endpoints:
   ```
   Deprecation: true
   ```
3. **Add a `Sunset` header** with the planned removal date (RFC 7231):
   ```
   Sunset: Sat, 01 Jan 2028 00:00:00 GMT
   ```
4. **Document in CHANGELOG.md** under a "Deprecated" section following the [Keep a Changelog](https://keepachangelog.com/) format already in use.
5. **Log warnings** server-side when deprecated features are invoked, so operators can track usage before removal.
6. **Minimum notice period**: 90 days between the deprecation announcement and the release that removes the feature.

---

## API Versioning Strategy

- Current API version: **v1** (path prefix: `/api/v1/`)
- When v2 is released, both `/api/v1/` and `/api/v2/` will be served simultaneously by the same process.
- v1 will remain supported for **at least 12 months** after the first stable v2 release.
- No more than **two** API versions will be supported at the same time. When v3 ships, v1 reaches end-of-life.
- The `GET /health` response will continue to report the server version; it is not versioned per API path.

---

## Database Migration Compatibility

NIS2 Compass uses Alembic for schema migrations (see [migrations.md](migrations.md)).

| Rule | Detail |
|---|---|
| Every schema change ships with an Alembic migration | No manual DDL outside the migration chain |
| Migrations are forward-only in production | `alembic upgrade head` is the standard path |
| Rollback scripts are provided for emergencies | Tested in CI but not guaranteed under all data conditions |
| Minor-version schema changes are always additive | New tables, new nullable columns, new indexes |
| Destructive schema changes only in major versions | Column removal, column rename, type change, constraint tightening |

When a new nullable column is added in a minor release, existing rows receive `NULL` as the default value and existing queries remain valid.

---

## SDK Compatibility

The opensecstack SDK clients (Go, Python, TypeScript, Rust) follow the same versioning scheme:

- SDK **v1.x** works with NIS2 Compass API **v1.x**.
- New optional response fields added in a minor API release are silently ignored by older SDK versions that do not model them.
- New optional request fields added in a minor API release can be omitted by older SDK versions without effect.
- SDK major version bumps are aligned with API major version bumps.
- SDK patch releases may ship independently to fix client-side bugs that do not involve API changes.

---

## Client Guidelines

To ensure forward compatibility, API consumers should follow these practices:

1. **Ignore unknown JSON fields** — do not fail when the response contains fields your client does not recognise. New fields may appear in any minor release.
2. **Use pagination** — do not assume a fixed page size or a maximum total count. Always read the `X-Total-Count` header and iterate pages.
3. **Handle new enum values gracefully** — treat any unrecognised `status`, `risk_class`, `type`, or similar value as `"other"` or log-and-skip rather than raising an error.
4. **Check HTTP status codes first** — do not parse the `error` text for control flow; use the `code` field if you need programmatic error handling.
5. **Set the `Accept` header** — specify `application/json` explicitly on every request.
6. **Pin your SDK version** — use a lockfile (`package-lock.json`, `go.sum`, `Cargo.lock`, etc.) to avoid unintended upgrades.

---

## Release Cadence

| Release type | Frequency | Notice |
|---|---|---|
| **Patch** (1.0.X) | As needed; within 48 hours for critical CVEs | None required |
| **Minor** (1.X.0) | Monthly, or as features are ready | Release notes in CHANGELOG.md |
| **Major** (X.0.0) | At most annually | 90-day deprecation notice for removed features |

All releases are tagged in Git (`v1.0.0`, `v1.1.0`, etc.) and published as container images.

---

## Support Matrix

| Version | Status | Supported Until |
|---------|--------|-----------------|
| 1.0.x   | Active | Until 1.2.0 release + 30 days |
| 0.x     | End of life | No longer supported |

**Policy**: each minor release line receives patch updates until **two** newer minor releases have shipped, plus a 30-day grace period. For example, 1.0.x patches will continue until 30 days after 1.2.0 is released.

Security fixes for end-of-life versions are not back-ported unless contractually required.

---

## Changelog

All changes are documented in [CHANGELOG.md](../CHANGELOG.md) following the
[Keep a Changelog](https://keepachangelog.com/) format. Every pull request that
touches the API surface, database schema, or SDK contract must include a
CHANGELOG entry before merge.
