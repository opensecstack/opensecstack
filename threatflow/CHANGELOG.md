# Changelog

All notable changes to ThreatFlow are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- TAXII 2.1 feed polling with configurable intervals
- STIX 2.1 bundle export endpoint
- MITRE ATT&CK automatic TTP mapping
- IOC deduplication engine (hash + fuzzy)
- Feed confidence scoring (Bayesian)
- APIGuard scan target IOC extraction
- IRFlow incident context enrichment
- CITADEL MARSHAL governance for all mutations
- PostgreSQL persistence with full-text IOC search
- Redis caching for hot IOC lookups

## [0.1.0] — 2026-03-31

### Added
- Project scaffold: Cobra CLI, chi HTTP router, zerolog structured logging
- `threatflow serve` command — starts HTTP API on port 8091
- `threatflow version` command — prints version, commit, build date
- Health endpoint: `GET /api/v1/health`
- Version endpoint: `GET /api/v1/version`
- IOC endpoints (scaffold): `GET /api/v1/iocs`, `POST /api/v1/iocs`, `GET /api/v1/iocs/{id}`
- STIX bundle endpoints (scaffold): `GET /api/v1/stix/bundles`, `POST /api/v1/stix/bundles`
- Configuration via `THREATFLOW_` environment variables (Viper)
- CITADEL integration config (API URL, key ID, key secret, project ID)
- Dockerfile: two-stage Alpine build, non-root runtime user
- Kubernetes manifests: Deployment, Service, Ingress, HPA
- 8 handler tests (health, version, IOC CRUD, STIX bundles)
- Full documentation suite (11 docs)
