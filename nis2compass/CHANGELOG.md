# Changelog

All notable changes to NIS2 Compass are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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
- Alembic migrations: versioned schema migrations (001–012)
- NIS2 control seeds: Article 21(2) measures a–j with NIST CSF mapping
- Kubernetes manifests: deployment, service, and ingress for NIS2 Compass and its dependencies
- Docker Compose stacks: development and production configurations
- Webhook support: receive scan results from APIGuard and platform events from other opensecstack platforms
- Test suite: 10 test modules covering all major API endpoints and audit chain integrity

---

## [0.1.0] — Unreleased

Initial release. See [Unreleased] above for the full feature list.
