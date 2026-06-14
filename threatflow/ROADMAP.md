# ThreatFlow Roadmap

## v0.1.0 — Scaffold (Current)

| Feature | Status |
|---------|--------|
| HTTP API scaffold (health, version, IOC, STIX endpoints) | Done |
| Cobra CLI with serve + version commands | Done |
| Configuration via environment variables | Done |
| Dockerfile + Kubernetes manifests | Done |
| Handler test suite (8 tests) | Done |
| Documentation (11 docs) | Done |

## v0.2.0 — Persistence + Basic Ingestion

| Feature | Status |
|---------|--------|
| PostgreSQL schema: IOCs, feeds, STIX objects, bundles | Planned |
| Database migrations via golang-migrate | Planned |
| IOC CRUD with full persistence | Planned |
| STIX 2.1 bundle parsing and storage | Planned |
| IOC deduplication (SHA-256 hash matching) | Planned |
| Pagination on all list endpoints | Planned |
| JWT authentication on mutation endpoints | Planned |
| CITADEL WORM event emission on IOC ingestion | Planned |

## v0.3.0 — Feed Polling + ATT&CK Mapping

| Feature | Status |
|---------|--------|
| TAXII 2.1 client: poll external feeds on configurable intervals | Planned |
| CSV feed importer (AlienVault OTX, abuse.ch format) | Planned |
| MISP feed importer (MISP JSON format) | Planned |
| MITRE ATT&CK mapping: automatic TTP tagging via keyword + pattern | Planned |
| Feed confidence scoring: Bayesian model per source | Planned |
| IOC aging and expiry: configurable TTL per feed | Planned |
| CITADEL MARSHAL governance: ingestion requires EXECUTE decision | Planned |

## v0.4.0 — Correlation + Ecosystem Integration

| Feature | Status |
|---------|--------|
| APIGuard integration: extract IOCs from scan targets | Planned |
| IRFlow integration: enrich incidents with IOC context | Planned |
| NIS2 Compass integration: map IOCs to supply chain evidence | Planned |
| Cross-feed correlation: link related IOCs across sources | Planned |
| STIX 2.1 relationship objects: indicator → attack-pattern links | Planned |
| Bulk export API: filtered STIX bundles for downstream consumers | Planned |
| Webhook notifications on high-confidence IOC matches | Planned |

## v0.5.0 — Production Readiness

| Feature | Status |
|---------|--------|
| Redis caching for hot IOC lookups | Planned |
| Rate limiting on ingestion endpoints | Planned |
| Full-text search across IOC metadata | Planned |
| React dashboard: feed status, IOC trends, ATT&CK heatmap | Planned |
| Grafana metrics: ingestion rate, correlation latency, feed health | Planned |
| Security audit and penetration testing | Planned |
| Performance benchmarks: 10K IOCs/sec ingestion target | Planned |
| High-availability deployment guide | Planned |

## How We Plan

- Roadmap is updated quarterly
- Community input via [GitHub Discussions](https://github.com/opensecstack/opensecstack/discussions)
- Significant changes require an RFC
- Architecture decisions are recorded in ADRs
