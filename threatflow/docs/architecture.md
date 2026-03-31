# ThreatFlow Architecture

## Overview

ThreatFlow is a Go service that acts as the threat intelligence hub for the opensecstack ecosystem. It ingests indicators of compromise (IOCs) from multiple feed types, normalises them to STIX 2.1 format, correlates them with internal platform data, and publishes enriched intelligence bundles.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        ThreatFlow :8091                         │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────────┐  │
│  │  Feed    │   │  STIX    │   │ Correlat-│   │  Export    │  │
│  │  Poller  │──▶│  Parser  │──▶│   ion    │──▶│  Engine   │  │
│  └──────────┘   └──────────┘   │  Engine  │   └─────┬──────┘  │
│       ▲                        └────┬─────┘         │          │
│       │                             │               │          │
│  ┌────┴─────┐                  ┌────▼─────┐    ┌────▼──────┐  │
│  │  Feed    │                  │ ATT&CK   │    │  STIX 2.1 │  │
│  │  Config  │                  │  Mapper  │    │  Bundles  │  │
│  └──────────┘                  └──────────┘    └───────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    PostgreSQL (IOC store)                 │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HMAC-SHA256 signed events
                            ▼
                     ┌──────────────┐
                     │   CITADEL    │
                     │   :8099      │
                     └──────────────┘
```

---

## Data Flow

### Ingestion

1. **Feed Poller** pulls IOCs from configured sources (TAXII 2.1, CSV, MISP, manual API)
2. **STIX Parser** normalises all indicators to STIX 2.1 Indicator objects
3. **Deduplicator** checks SHA-256 of indicator pattern to prevent duplicates
4. **MARSHAL gate** (via CITADEL) evaluates whether the ingestion should proceed
5. **PostgreSQL** stores the normalised IOC with feed metadata and confidence score
6. **WORM event** emitted to CITADEL: `threatflow.ioc.ingested`

### Correlation

1. **Correlation Engine** cross-references new IOCs with:
   - APIGuard scan findings (matching target URLs, IPs)
   - IRFlow open incidents (matching indicator values)
   - Existing IOCs from other feeds (shared infrastructure detection)
2. Matches produce STIX Relationship objects linking indicators to observed data
3. High-confidence matches trigger webhook notifications

### Export

1. **Export Engine** assembles STIX 2.1 bundles on demand or on schedule
2. Bundles are filtered by consumer (IRFlow gets incident-relevant IOCs, APIGuard gets URL/domain IOCs)
3. Each export is WORM-logged with bundle hash for audit trail

---

## Integration Points

| Platform | Direction | Data | Format |
|----------|-----------|------|--------|
| APIGuard | ThreatFlow ← APIGuard | Scan target URLs for IOC extraction | JSON event |
| APIGuard | ThreatFlow → APIGuard | Known malicious URLs/IPs for scan enrichment | STIX 2.1 |
| IRFlow | ThreatFlow → IRFlow | IOC context for open incidents | STIX 2.1 bundle |
| IRFlow | ThreatFlow ← IRFlow | Incident artifacts for retroactive IOC matching | JSON event |
| NIS2 Compass | ThreatFlow → NIS2 Compass | Supply chain IOCs as evidence artifacts | STIX 2.1 |
| CITADEL | ThreatFlow → CITADEL | WORM events for all ingestion/export operations | HMAC-signed JSON |
| CITADEL | ThreatFlow ← CITADEL | MARSHAL decisions (EXECUTE/REFUSE/HARD_STOP) | JSON response |

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Go 1.22+ | HTTP service, feed polling, correlation |
| HTTP framework | chi v5 | Routing, middleware |
| CLI | Cobra + Viper | Command-line interface, config |
| Database | PostgreSQL 16 | IOC persistence, full-text search |
| Cache | Redis 7 | Hot IOC lookup, feed poll state |
| Logging | zerolog | Structured JSON logging |
| Auth | JWT (consumer API) + HMAC-SHA256 (CITADEL) | Dual auth model |
| Container | Alpine 3.19 | Minimal runtime image |
| Orchestration | Kubernetes | Production deployment |

---

## Directory Structure

```
threatflow/
├── cmd/threatflow/
│   ├── main.go                 # Entrypoint
│   └── cmd/
│       ├── root.go             # Cobra root + Viper config
│       ├── serve.go            # HTTP server command
│       └── version.go          # Version command
├── internal/
│   ├── api/
│   │   ├── server.go           # chi router + middleware
│   │   └── handlers/
│   │       ├── health.go       # Health + version endpoints
│   │       └── ioc.go          # IOC + STIX endpoints
│   ├── config/
│   │   └── config.go           # Viper config struct
│   ├── version/
│   │   └── version.go          # Build-time version info
│   ├── feed/                   # [Planned] Feed polling
│   ├── stix/                   # [Planned] STIX 2.1 parser
│   ├── correlate/              # [Planned] Correlation engine
│   └── db/                     # [Planned] PostgreSQL layer
├── docs/                       # Documentation
├── Dockerfile
├── go.mod

---

## See Also

- [API Reference](api-reference.md) — HTTP endpoints documented here
- [Data Model](data-model.md) — PostgreSQL schema backing the IOC store
- [STIX 2.1 Integration](stix-integration.md) — STIX object flow through the system
- [IOC Feeds](ioc-feeds.md) — feed ingestion pipeline detail
- [CITADEL Integration](citadel-integration.md) — governance layer in the architecture
- [Deployment](deployment.md) — running this architecture in Docker / Kubernetes
└── go.sum
```
