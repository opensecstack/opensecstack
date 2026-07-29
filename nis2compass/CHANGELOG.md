# Changelog

All notable changes to NIS2 Compass are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

- Real CITADEL governance integration: `app/citadel_client.py` implements `POST /api/v1/worm/emit` (fire-and-forget audit forwarding) and `POST /api/v1/marshal/evaluate` (synchronous, fail-closed governance evaluation). Wired into four privileged actions — control status update, artifact signing, assessment lock, and assessment unlock — each of which now blocks (`403`/`503`) on a `REFUSE`/`HARD_STOP` verdict or an unreachable CITADEL, instead of proceeding un-governed. No-op (proceeds as before) when `CITADEL_API_URL` is not set.
- Real Separation-of-Duties for artifact signing: `Artifact.created_by` (the preparer) is sent to CITADEL as `Verifier` against the signer as `Actor` — a genuine second identity, not the placeholder verifier used by the other three governed actions.
- `app/auth.py`'s `require_auth` now stashes the raw bearer token (`g.raw_token`) and actor email (`g.actor_email`) on the request context, forwarded to CITADEL as `Kerkese.ActorToken`/`Actor.Email`.
- Alembic migration 020: adds the missing `assessments.created_by` column (declared on the model, used by `app/api/assessments.py`, but never migrated — every assessment creation was failing with `column assessments.created_by does not exist`).

### Fixed

- CITADEL audit forwarding was completely broken: `app/audit.py` posted to `{citadel_url}/v1/log`, a route that never existed on CITADEL (not even under `/api/v1/`). Every forwarded audit event silently failed regardless of `CITADEL_API_URL` being configured. Now routes through `citadel_client.emit_worm()` against the real `/api/v1/worm/emit` endpoint.
- `write_audit()` calls in `app/api/compliance.py` (score, approve/reject, lock, unlock, sign, gap-analysis) were missing a required positional argument and crashed on every call.
- Audit entries for CITADEL-forwarded events could be lost when a transaction rolled back after a premature commit; forwarding is now correctly deferred until after the database transaction actually commits.
- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE).
- `app/sinauth.py` — OIDC token validation module; verifies RS256 tokens against the sinauth JWKS endpoint.
- `sinauth.ts` client added to the web dashboard for popup-based SSO login.
- Compliance score history: `ComplianceSnapshot` model records a snapshot every time a score is computed; new `GET /api/v1/assessments/<id>/history` endpoint returns all snapshots ordered by time
- NCA export format: `app/reporters/nca_reporter.py` generates a structured XML report for submission to National Competent Authorities; available via `POST /api/v1/assessments/<id>/report?format=nca`
- Alembic migration 014: creates `compliance_snapshots` table
- Artifact type `pentest`: pentest reports can now be uploaded as evidence artifacts
- Notification system: `app/notifications.py` dispatches webhook POSTs on assessment status changes and control overdue events; optional SMTP email support via `NIS2_SMTP_*` env vars

---

## [1.0.0] — 2026-03-31

### Added

- Organisation management: create, update, and manage NIS2-subject organisations with entity type (essential/important), industry, country, and size classification
- Assessment lifecycle: full draft → in_progress → under_review → completed workflow for NIS2 Article 21 assessments
- Control framework: 10 NIS2 Article 21(2) measures (a–j) pre-seeded as control templates, automatically attached to each assessment
- Evidence management: file artifact upload linked to assessments and individual controls with SHA-256 integrity hash
- Remediation tracking: gap description, remediation plan, due date, owner, and status per control
- Immutable audit log: every API action logged with chain hash (SHA-256 of content + prev_hash) for tamper detection
- API key authentication: scoped API keys with SHA-256 storage (plaintext never retained after creation)
- JWT authentication: access + refresh token pair, revocation support
- Rate limiting: sliding-window Redis-backed rate limiter on all endpoints
- CORS: configurable allowed origins, deny-all default in production
- OpenAPI spec endpoint: machine-readable API contract at `/api/v1/openapi.json`
- React web dashboard: organisation list, assessment detail, control assessment, audit log viewer
- Alembic migrations: versioned schema migrations (001–013)
- NIS2 control seeds: Article 21(2) measures a–j with NIST CSF mapping
- Kubernetes manifests: deployment, service, and ingress for NIS2 Compass and its dependencies
- Docker Compose stacks: development and production configurations
- Webhook support: receive scan results from APIGuard and platform events from other opensecstack platforms
- Test suite: 10 test modules covering all major API endpoints and audit chain integrity
