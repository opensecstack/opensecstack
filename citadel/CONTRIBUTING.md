# Contributing to CITADEL

CITADEL is the cryptographic governance engine of OpenSecStack. Because
it anchors the audit chain every other platform relies on, contributions
are held to a higher correctness bar than typical application code: a
bug here does not stop a feature — it silently degrades the trust
guarantees of everything downstream.

## Licence

CITADEL is **AGPL-3.0**. Tool platforms in this monorepo (APIGuard,
ThreatFlow, SDKs) remain Apache-2.0 — contributing to CITADEL means
accepting the copyleft obligation for modifications distributed as a
network service. See [LICENSE](LICENSE) for the rationale.

## Development setup

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/citadel

# Start the containerised Postgres (docker-compose exposes it on :5434)
make docker-up

# Apply migrations to the running DB
make migrate

# Run CITADEL against it
make run

# In another terminal
make health   # → {"status":"ok","db":"ok","version":"...","commit":"..."}
```

## Required tools

- Go 1.24+
- Docker + Docker Compose
- PostgreSQL 16 client (`psql`) — only for `make migrate`
- `golangci-lint` (installed by CI; run `make lint` locally)

## Code style

- `gofmt`-clean; the lint config (`.golangci.yml`) enforces `goimports`,
  `staticcheck`, `errcheck`, `gosec`, `bodyclose`.
- Errors: wrap with `fmt.Errorf("%w: …", err)`. Sentinel errors belong
  next to the types they relate to (`var ErrFoo = errors.New(...)`).
- Logging: `zerolog` with service/component fields — no `fmt.Sprintf`
  inside log messages.
- Benchmarks: any new hot-path code under `internal/marshal` or
  `internal/db` needs a benchmark in `benches/` before merging. Compare
  against the v1.0.0 baseline in [CHANGELOG.md](CHANGELOG.md#performance-intel-core-i7-7600u-go-1244).

## Migrations — the hard rule

The WORM chain depends on stable bytes. That means:

- **Never** modify a committed migration. Add a new one (`NNN_description.sql`)
  that evolves the schema forward.
- Migrations that touch WORM tables (`worm_entries`, `chain_anchors`)
  require an ADR justifying the change.
- The `chain_hash` column must never be altered retroactively — if the
  hash domain needs to change, it becomes a v2 anchor with a new table.

## Testing

| Command | Scope |
|---|---|
| `make test` | Unit tests — fast, no Docker |
| `make bench` | Performance benchmarks under `-tags bench` |
| `make lint` | golangci-lint |

Integration tests run against the containerised Postgres; the test
suite truncates between runs but relies on `make docker-up` being
active.

## Pull request checklist

- [ ] `make test` and `make lint` pass.
- [ ] Benchmarks updated if hot-path changed; no regression > 10% vs
      baseline without an accompanying justification.
- [ ] CHANGELOG.md `[Unreleased]` section updated.
- [ ] Any new MARSHAL gate, WORM behaviour, or key-handling change
      reviewed by at least one reviewer other than the author.
- [ ] Migrations follow the append-only rule above.

## Commit message format

[Conventional Commits](https://www.conventionalcommits.org/). Scope
corresponds to top-level package: `marshal`, `worm`, `db`, `api`, etc.

```
feat(marshal): add gate 4 off-hours heuristic

Emits AUGUR_rule_01 when an action is initiated outside the configured
business-hours window. Behind CITADEL_MARSHAL_STRICT_HOURS flag.

Closes #234
```

## Reporting security issues

See [SECURITY.md](SECURITY.md). **Never open a public issue for a bug
in the WORM chain or MARSHAL gates.**

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).
