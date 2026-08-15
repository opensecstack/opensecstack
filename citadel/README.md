# CITADEL — Cryptographic Governance Engine

CITADEL is the central governance engine for the opensecstack (SIN — Security Intelligence Network) ecosystem. Every privileged action across the ecosystem's platforms is meant to pass through CITADEL's 5-gate MARSHAL decision engine before execution. Nine producer platforms (apiguard, irflow, threatflow, opencsirt, openscrub, securelab, community, cyberpath, nis2compass) are wired to submit real Kerkese requests today — see [Known limitations](#known-limitations) for a gap that currently causes most of those real calls to `REFUSE`.

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
| `POST` | `/api/v1/keys/register` | Register an Ed25519 public signing key for a sinauth `user_id` |
| `GET` | `/api/v1/keys/{user_id}` | Look up the active signing key metadata for a `user_id` |

Generate a personal Operator/Verifier keypair with the CLI (private key never leaves your machine):

```bash
citadel keygen -out . -label myname
# writes myname.key (0600, local only) and prints a ready-to-run
# curl for POST /api/v1/keys/register
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CITADEL_PORT` | `8099` | HTTP port |
| `CITADEL_DB_URL` | — | PostgreSQL connection string |
| `CITADEL_LOG_LEVEL` | `info` | Log level |
| `CITADEL_CITADEL_MASTER_KEY` | — | Ed25519 master key (hex) for WORM anchors |
| `CITADEL_CITADEL_ANCHOR_INTERVAL` | `100` | WORM entries between anchor signatures |
| `CITADEL_CITADEL_SINAUTH_ISSUER_URL` | — | **Required.** sinauth OIDC issuer CITADEL verifies Actor/Verifier bearer tokens against. Server fails to start without it. |
| `CITADEL_CITADEL_ENFORCE_IDENTITY` | `false` | When `true`, Gate 1/Gate 3 `REFUSE` if the sinauth bearer token (`actor_token`/`verifier_token`) is missing, invalid, or doesn't match the claimed `user_id`. Off by default — see [Known limitations](#known-limitations). |
| `CITADEL_CITADEL_ENFORCE_SIGNATURES` | `false` | When `true`, Gate 1/Gate 3 `REFUSE` if the Operator/Verifier Ed25519 signature (`sig_operator`/`sig_verifier`) is missing, unregistered, or invalid. Off by default — no producer platform signs every Kerkese yet. |
| `CITADEL_CITADEL_PERMIFY_URL` | `""` | The Permify instance/schema sinauth's `internal/authz` writes to (see sinauth's `adrs/006-permify-authorization-engine.md`). Empty → the Gate 2 Permify sub-check is a no-op PASS for every role/action, identical to rbacMap-only behavior. |
| `CITADEL_CITADEL_ENFORCE_PERMIFY_AUTHZ` | `false` | When `true`, Gate 2 `REFUSE`s a role/action explicitly denied by the synced Permify snapshot (`known=true, allowed=false`), in addition to the always-enforced `rbacMap` check. Off by default (soft-launch) — a known-deny only `WARN`s until this is enabled. See [ADR-007](./adrs/007-permify-gate2-snapshot.md). |
| `CITADEL_CITADEL_PERMIFY_SYNC_INTERVAL` | `5m` | How often `internal/permifysync`'s ticker goroutine refreshes the local `permify_role_action_snapshot` table Gate 2 reads from. |

See [docs/configuration.md](./docs/configuration.md) for the full reference.

## Architecture

```
Request → Gate 1 (AuthN) → Gate 2 (AuthZ) → Gate 3 (NDS) → Gate 4 (AUGUR) → Gate 5 (WORM)
                                                                                      ↓
                                                                              Always logged
```

- **Gate 1 — AuthN**: verifies the Actor's sinauth bearer token (`actor_token`) and Ed25519 signature (`sig_operator`) against a registered key. Both checks always run and are recorded; each only blocks the gate if its own enforce flag (`enforce_identity` / `enforce_signatures`) is on — both are **off by default** (soft mode), so today Gate 1 warns rather than refuses on missing identity/signature.
- **Gate 2 — AuthZ**: two checks composed via `combineChecks`. Check A (`rbacMap`) is the permanent, unconditional safety net — a fixed 5-role matrix (`admin`, `operator`, `analyst`, `viewer`, `auditor`), always enforced, never weakened by anything below. Check B is a new, optional soft-launch check against a periodically-refreshed local snapshot of Permify-derived role→action policy (`internal/permifysync`, no live per-request call to Permify); it defaults off (`EnforcePermifyAuthz` / `CITADEL_CITADEL_ENFORCE_PERMIFY_AUTHZ` = `false`) and an unknown role/action pair from Permify's side is always treated as PASS, never REFUSE. `rbacMap` still does not yet have entries for most of the 9 producer platforms' real action types — see [Known limitations](#known-limitations) and [ADR-007](./adrs/007-permify-gate2-snapshot.md).
- **Gate 3 — NDS**: Operator ≠ Verifier and different role groups (unconditional `HARD_STOP` if violated), plus the same soft-gated token/signature checks as Gate 1, this time for the Verifier.
- **Gate 4 — AUGUR**: 3 behavioral heuristic rules (off-hours action, >10 actions/5min for one actor, `DATA_EXPORT` without `incident_id` → unconditional `HARD_STOP`)
- **Gate 5 — WORM**: Unconditional append-only log with TripleHash; bearer tokens are redacted before archiving, signatures are persisted as long-term evidence

## Known limitations

- **`rbacMap`/`roleGroupMap` coverage gap.** Nine producer platforms (apiguard, irflow, threatflow, opencsirt, openscrub, securelab, community, cyberpath, nis2compass) now submit real Kerkese requests to MARSHAL, but `internal/marshal/types.go`'s `rbacMap`/`roleGroupMap` only cover a handful of legacy action types (`API_SCAN_INITIATE`, `INCIDENT_CREATE`, `DATA_EXPORT`, `CONFIG_CHANGE`, `USER_CREATE`/`DELETE`, `PLAYBOOK_EXECUTE`, `IOC_INGEST`). Every real `evaluate()` call whose `action.type` or `actor.role` isn't in those maps will currently `REFUSE` at Gate 2 (AuthZ). This is a real, open gap, not yet fixed. A Permify-based mitigation now exists in soft-launch form ([ADR-007](./adrs/007-permify-gate2-snapshot.md)) but does not yet close this gap: the synced snapshot is currently expected to be empty, since sinauth's Permify schema doesn't yet model CITADEL's action-type vocabulary. **For the exact per-platform action-type/role audit — which of the 9 platforms' real calls pass Gate 2 today (as of this writing, only one does) versus which `REFUSE` and why — see [docs/known-limitations.md § `rbacMap`/`roleGroupMap` coverage gap](./docs/known-limitations.md#rbacmaprolegroupmap-coverage-gap-gate-2).**
- **`enforce_identity` and `enforce_signatures` are both `false` by default.** Identity (sinauth token) and signature (Ed25519) checks run and are recorded in `gates[]`, but neither blocks a decision today — see [ADR-006](./adrs/006-split-enforce-identity-and-signatures.md) for why, and what has to be true before each can be turned on. See also [docs/known-limitations.md § soft enforcement](./docs/known-limitations.md#enforce_identity--enforce_signatures-default-to-false-soft-enforcement) for what this means in practice given today's Gate 2 coverage.

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
- [x] Session 5: Operator/Verifier Ed25519 signatures ([ADR-004](./adrs/004-operator-verifier-ed25519-signatures.md)), sinauth identity bridge replacing the dead `sessions` table ([ADR-005](./adrs/005-sinauth-identity-bridge.md)), split `enforce_identity`/`enforce_signatures` rollout flags ([ADR-006](./adrs/006-split-enforce-identity-and-signatures.md))

## Running Benchmarks

```bash
# All benchmarks (no DB required — uses mock store)
go test -tags bench -bench=. -benchmem -count=10 ./benches/

# Unit tests only (no DB required)
go test ./internal/marshal/... ./internal/db/... -v

# Expected benchmark output (IEEE paper Table II; predates the Ed25519 +
# sinauth-token checks added in Gate 1/Gate 3 — figures have not yet been
# re-measured with those checks live):
# BenchmarkMARSHAL_Evaluate        — ~2-6ms/op (all 5 gates + mock WORM)
# BenchmarkTripleHash_1KB           — ~0.3-0.6ms/op
# BenchmarkWORM_ChainStep           — ~0.1-0.2ms/op
# BenchmarkWORM_FullEntry           — ~0.4-0.7ms/op
```

## License

**AGPL-3.0-or-later** — see [LICENSE](LICENSE). CITADEL is the trust root
of the OpenSecStack ecosystem: its WORM audit chain and MARSHAL governance
gates are what downstream platforms — and ultimately regulators — rely on
for tamper-evident evidence. AGPL-3.0 ensures that any modified version
operated as a network service must publish its source to its users,
preventing a closed-source fork of the governance layer from diverging
silently from the upstream audit semantics. Tool platforms in this
monorepo (APIGuard, ThreatFlow, SDKs) remain Apache-2.0 — the copyleft
obligation is scoped to the governance core by design. See the
[monorepo ECOSYSTEM.md — Licensing Model](https://github.com/opensecstack/opensecstack/blob/main/ECOSYSTEM.md#licensing-model).
