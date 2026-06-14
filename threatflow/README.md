# ThreatFlow

**Threat intelligence aggregation and correlation for the opensecstack ecosystem.**

ThreatFlow ingests IOC feeds from external and internal sources, maps indicators to the MITRE ATT&CK framework, and publishes STIX 2.1 intelligence bundles. Every ingestion, correlation, and enrichment operation is WORM-logged via CITADEL MARSHAL governance.

---

## What It Does

- **IOC ingestion** — pull from TAXII 2.1 servers, CSV feeds, MISP instances, and manual uploads
- **STIX 2.1 native** — all intelligence objects stored and exchanged as STIX 2.1 bundles
- **MITRE ATT&CK mapping** — automatic TTP classification for indicators and observed patterns
- **Correlation engine** — cross-reference IOCs with APIGuard scan findings and IRFlow incidents
- **Feed scoring** — confidence scoring per feed source based on historical accuracy
- **CITADEL governance** — every ingestion and enrichment decision evaluated by MARSHAL, logged to WORM
- **NIS2 alignment** — contributes to Article 21(2)(b) incident handling and (d) supply chain security

---

## Coverage

| Capability | Status | Details |
|-----------|--------|---------|
| IOC ingestion (manual) | v1.0 | `POST /api/v1/iocs` with pattern-hash dedup |
| IOC ingestion (TAXII 2.1 polling) | v1.0 | Scheduler polls enabled feeds at the configured interval |
| CSV feed polling (abuse.ch, OTX) | v1.0 | Column auto-detection, `#`-comment stripping |
| MISP feed polling | v1.0 | `/events/restSearch` consumer, `to_ids=true` filter |
| STIX 2.1 bundle ingestion | v1.0 | Parser + validator + importer with dedup |
| STIX 2.1 bundle fetch | v1.0 | `GET /api/v1/stix/bundles/{id}` returns envelope + objects |
| MITRE ATT&CK mapping | v1.0 | 19 embedded techniques + 16 auto rules + feed-provided extraction |
| IOC correlation engine | v1.0 | 5 rules (duplicate, resolves-to, subdomain-of, same-network, shares-cve) |
| Feed confidence base | v1.0 | Per-feed `confidence_base` propagated to IOCs on ingest |
| APIGuard + IRFlow + NIS2 integration | v1.0 | HMAC-signed outbound webhooks + `POST /sightings` ingress |
| Match lookup | v1.0 | `GET /match?type=X&value=Y` with Redis cache |
| CITADEL MARSHAL governance | v1.0 | Every mutation gated (`IOC_INGEST`, `STIX_BUNDLE_IMPORT`, ...) |
| CITADEL WORM logging | v1.0 | Bounded async queue with graceful drain |
| JWT auth + API keys + RBAC | v1.0 | HS256 tokens; 4 roles; SHA-256 hashed keys |
| Redis match cache | v1.0 | 10-minute TTL, invalidated on upsert/revoke |
| Rate limiting | v1.0 | Per-IP token bucket, configurable rps + burst |
| Integration + E2E tests | v1.0 | `make test-e2e` exercises the full paper flow |

---

## Quick Start

```bash
# Clone and run locally
cd threatflow
go run ./cmd/threatflow serve

# Or with Docker
docker build -t threatflow .
docker run -p 8091:8091 threatflow

# Health check
curl http://localhost:8091/api/v1/health
# {"service":"threatflow","status":"ok"}

# Ingest an IOC
curl -X POST http://localhost:8091/api/v1/iocs \
  -H "Content-Type: application/json" \
  -d '{"type":"ipv4-addr","value":"198.51.100.42","source":"manual"}'

# Ingest a STIX bundle
curl -X POST http://localhost:8091/api/v1/stix/bundles \
  -H "Content-Type: application/json" \
  -d '{"type":"bundle","id":"bundle--abc123","objects":[]}'
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Service health |
| GET | `/api/v1/version` | Version info |
| GET | `/api/v1/iocs` | List all IOCs |
| POST | `/api/v1/iocs` | Ingest a new IOC |
| GET | `/api/v1/iocs/{id}` | Get IOC by ID |
| GET | `/api/v1/stix/bundles` | List STIX bundles |
| POST | `/api/v1/stix/bundles` | Ingest a STIX 2.1 bundle |

See [docs/api-reference.md](docs/api-reference.md) for full details.

---

## Architecture

```
                  ┌──────────────┐
  TAXII 2.1 ────▶│              │
  CSV feeds ────▶│  ThreatFlow  │──▶ STIX 2.1 bundles ──▶ IRFlow
  MISP      ────▶│   :8091      │──▶ IOC context     ──▶ APIGuard
  Manual    ────▶│              │
                  └──────┬───────┘
                         │ WORM events
                         ▼
                  ┌──────────────┐
                  │   CITADEL    │
                  │   :8099      │
                  └──────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the full design.

---

## Configuration

ThreatFlow is configured via environment variables with the `THREATFLOW_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_PORT` | `8091` | HTTP listen port |
| `THREATFLOW_DB_URL` | `postgres://...` | PostgreSQL connection string |
| `THREATFLOW_CITADEL_API_URL` | *(empty — disabled)* | CITADEL base URL |
| `THREATFLOW_CITADEL_KEY_ID` | | HMAC connector key ID |
| `THREATFLOW_CITADEL_KEY_SECRET` | | HMAC signing secret |
| `THREATFLOW_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `THREATFLOW_LOG_FORMAT` | `json` | Log format (json, text) |

See [docs/configuration.md](docs/configuration.md) for the full reference.

---

## Authentication

ThreatFlow authenticates operators via [sinauth](../sinauth/docs/integration/threatflow.md) SSO — the SIN identity provider (OAuth 2.0 / OIDC, authorization code + PKCE).
Access tokens are RS256-signed JWTs issued by `https://auth.sin.to`; ThreatFlow validates them against the sinauth JWKS endpoint at `https://auth.sin.to/.well-known/jwks.json`.
See the [sinauth integration guide](../sinauth/docs/integration/threatflow.md) for token validation setup, RBAC mapping, and MFA configuration.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, data flow, component interactions |
| [API Reference](docs/api-reference.md) | Complete HTTP API documentation |
| [STIX 2.1 Integration](docs/stix-integration.md) | STIX object types, bundle format, TAXII polling |
| [IOC Feeds](docs/ioc-feeds.md) | Feed sources, ingestion pipeline, deduplication |
| [MITRE ATT&CK Mapping](docs/mitre-attack.md) | TTP classification and tagging |
| [Data Model](docs/data-model.md) | Database schema and relationships |
| [CITADEL Integration](docs/citadel-integration.md) | MARSHAL governance, WORM logging |
| [Security Model](docs/security-model.md) | Authentication, authorization, data protection |
| [Security Guide](docs/security.md) | Operational security configuration, TLS, secrets, rate limiting |
| [Compliance](docs/compliance.md) | NIS2 Directive Article 21(2) compliance mapping and evidence |
| [Integration Guide](docs/integration.md) | Cross-platform integration architecture and flows |
| [Webhook Specification](docs/webhook-spec.md) | Webhook protocol, signatures, retry policy, payloads |
| [Configuration](docs/configuration.md) | Environment variables, config file format |
| [Deployment](docs/deployment.md) | Docker, Kubernetes, production checklist |
| [Operator Handbook](docs/operator-handbook.md) | Day-to-day operations, monitoring, and runbooks for production |
| [Performance](docs/performance.md) | Throughput targets, database optimization, caching, scaling |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
| [Migrations](docs/migrations.md) | Database schema migrations with golang-migrate |
| [Testing](docs/testing.md) | Testing strategy, conventions, and unit/integration/e2e patterns |
| [Contributing](docs/contributing.md) | Development setup, coding conventions, pull request process |
| [FAQ](docs/faq.md) | Frequently asked questions about ThreatFlow |

---

## Licence

Apache 2.0 — see [LICENSE](../LICENSE).
