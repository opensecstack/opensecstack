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
| IOC ingestion (manual) | Scaffold | POST /api/v1/iocs |
| IOC ingestion (TAXII 2.1 polling) | Planned | Scheduled feed polling |
| STIX 2.1 bundle ingestion | Scaffold | POST /api/v1/stix/bundles |
| STIX 2.1 bundle export | Planned | GET with content negotiation |
| MITRE ATT&CK mapping | Planned | Automatic TTP tagging |
| IOC deduplication | Planned | Hash-based + fuzzy matching |
| Feed confidence scoring | Planned | Bayesian scoring per source |
| APIGuard integration | Planned | IOC extraction from scan targets |
| IRFlow integration | Planned | Context enrichment for incidents |
| CITADEL MARSHAL governance | Planned | All mutations MARSHAL-gated |
| CITADEL WORM logging | Planned | All operations chain-hashed |

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
| [Configuration](docs/configuration.md) | Environment variables, config file format |
| [Deployment](docs/deployment.md) | Docker, Kubernetes, production checklist |
| [Security Model](docs/security-model.md) | Authentication, authorization, data protection |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |

---

## Licence

Apache 2.0 — see [LICENSE](../LICENSE).
