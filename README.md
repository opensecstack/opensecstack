# opensecstack

> Open source cybersecurity ecosystem for Europe and beyond.

8 integrated security platforms + 1 governance layer. Built for NIS2 compliance, incident response, threat intelligence, and security operations.

## The Ecosystem

| Platform | What It Does | Language | Licence |
|----------|-------------|----------|---------|
| [**APIGuard**](apiguard/) | API security testing — OWASP API Top 10 | Go + Rust | Apache 2.0 |
| **NIS2 Compass** | NIS2 Article 21 compliance assessment & reporting | Python + Go | AGPL-3.0 |
| **ThreatFlow** | Threat intelligence aggregation, correlation & IOC management | Rust + Go | Apache 2.0 |
| **IRFlow** | Incident response orchestration with NIS2 notification support | Go + Python | AGPL-3.0 |
| **OpenScrub** | DDoS mitigation via XDP/eBPF at kernel level | Rust + C | Apache 2.0 |
| **CyberPath** | Security awareness training & certification platform | Go + React | Apache 2.0 |
| **SecureLab** | Attack simulation & detection rule validation | Python + Rust | Apache 2.0 |
| **OpenCSIRT** | National/sector CSIRT operations & advisory management | Go + Python | AGPL-3.0 |

**Governance:** [**CITADEL**](.citadel/) — audit trail, evidence chain, separation of duties, MARSHAL authorisation engine. Built by Security Intelligence Group (SIG).

## Architecture

All platforms communicate through the [opensecstack SDK](sdk/) using typed contracts. Every action can be governed by CITADEL with append-only WORM logs, SHA-256 chain anchors, and separation of duties enforcement.

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full architecture diagram and data flow map.

## Quick Start

```bash
# Clone the ecosystem
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# Start the full local stack
docker compose -f deploy/docker-compose.yml up

# Or start a single platform
cd apiguard && make dev
```

## Documentation

- [ECOSYSTEM.md](ECOSYSTEM.md) — Architecture diagram and integration map
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [SECURITY.md](SECURITY.md) — Vulnerability disclosure policy
- [ROADMAP.md](ROADMAP.md) — Public roadmap

### Platform Documentation

Each platform has its own `README.md`, architecture overview, quick start, and API reference in its directory.

## Community

- GitHub Discussions — questions, ideas, show & tell
- Discord — real-time chat (#general, #contributors, per-platform channels)
- Monthly community calls — open to everyone

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

## Contributing

We welcome contributions to any platform. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

**First time?** Look for issues labelled `good first issue` in any platform repo.

## Licence

- **Tool platforms** (APIGuard, ThreatFlow, OpenScrub, CyberPath, SecureLab): Apache 2.0
- **Governance platforms** (IRFlow, NIS2 Compass, OpenCSIRT, CITADEL): AGPL-3.0
- **SDK**: Apache 2.0

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full licensing rationale.
