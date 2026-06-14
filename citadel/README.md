# CITADEL — Cryptographic Governance Engine

CITADEL is the central governance engine for the opensecstack (SIN — Security Intelligence Network) ecosystem. Every privileged action across all 10 platforms (5 production + 4 planned + VertGuard proposed) passes through CITADEL's 5-gate MARSHAL decision engine before execution.

## Quick Start

```bash
# Start CITADEL + PostgreSQL
docker-compose up --build -d

# Verify health
curl http://localhost:8099/api/v1/health
# {"status":"ok","db":"ok"}
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Server + DB health |
| `POST` | `/api/v1/marshal/evaluate` | Evaluate Kerkese through 5 gates |
| `POST` | `/api/v1/worm/emit` | Append event to WORM chain |
| `GET` | `/api/v1/worm/verify` | Verify chain integrity |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CITADEL_PORT` | `8099` | HTTP port |
| `CITADEL_DB_URL` | — | PostgreSQL connection string |
| `CITADEL_LOG_LEVEL` | `info` | Log level |
| `CITADEL_CITADEL_MASTER_KEY` | — | Ed25519 master key (hex) for WORM anchors |
| `CITADEL_CITADEL_ANCHOR_INTERVAL` | `100` | WORM entries between anchor signatures |

## Architecture

```
Request → Gate 1 (AuthN) → Gate 2 (AuthZ) → Gate 3 (NDS) → Gate 4 (AUGUR) → Gate 5 (WORM)
                                                                                      ↓
                                                                              Always logged
```

- **Gate 1 — AuthN**: Ed25519 signature verification
- **Gate 2 — AuthZ**: RBAC permission check
- **Gate 3 — NDS**: Operator ≠ Verifier, different role groups
- **Gate 4 — AUGUR**: Behavioral heuristics (off-hours, frequency, anomalies)
- **Gate 5 — WORM**: Unconditional append-only log with TripleHash

## WORM Chain

Each entry is cryptographically linked:
```
chain_hash_n = SHA-256(chain_hash_{n-1} || payload_bytes)
triple_hash  = SHA-256(payload) || SHA-512(payload) || BLAKE3(payload)  // 128 bytes
```

## Development

```bash
# Run locally
make run

# Run tests
make test

# Run benchmarks
make bench

# Apply migrations
make migrate
```

## Session Progress

- [x] Session 1: Foundation (server, config, DB, routes, migrations, docker-compose)
- [x] Session 2: WORM chain — TripleHash + emit + verify
- [x] Session 3: MARSHAL 5 gates + NDS enforcement
- [x] Session 4: Benchmarks (marshal + worm + triplehash) + interface compliance check

## Running Benchmarks

```bash
# All benchmarks (no DB required — uses mock store)
go test -tags bench -bench=. -benchmem -count=10 ./benches/

# Unit tests only (no DB required)
go test ./internal/marshal/... ./internal/db/... -v

# Expected benchmark output (IEEE paper Table II):
# BenchmarkMARSHAL_Evaluate        — ~2-6ms/op (all 5 gates + mock WORM)
# BenchmarkTripleHash_1KB           — ~0.3-0.6ms/op
# BenchmarkWORM_ChainStep           — ~0.1-0.2ms/op
# BenchmarkWORM_FullEntry           — ~0.4-0.7ms/op
```
