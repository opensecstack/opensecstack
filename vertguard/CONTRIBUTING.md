# Contributing to VertGuard

VertGuard is the 10th opensecstack platform — AI-attack defence.
Contributions are welcome, especially for Phase 4.1 modules (Prompt
Injection Defence and AI Threat Intelligence Feed) which are in
active development.

## Licence

VertGuard is **AGPL-3.0**. Contributions are licensed under the same
terms. See [LICENSE](LICENSE).

If you contribute code that you want to also license under a
permissive licence elsewhere (Apache-2.0, MIT), open an issue first —
the core-maintainers review case-by-case.

## Development setup

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/vertguard

# Copy the example env
cp .env.example .env

# Start the integration test Postgres
docker compose -f docker-compose.test.yml up -d postgres

# Build + run unit tests
make build
make test
```

## Required tools

- Go 1.24+
- Rust 1.75+
- Docker + Docker Compose
- `golangci-lint` (for `make lint`)
- Python 3.10+ (only if working on Phase 4.2 ML layer)

## Code style

- **Go:** `gofmt` + `goimports`, enforced by `.golangci.yml` (same
  config as other platforms).
- **Rust:** `rustfmt` + `clippy` at `deny(warnings)` level.
- **Python** (Phase 4.2+): `black` + `isort` + `mypy`.
- **Errors:** return, don't panic. Wrap with `fmt.Errorf("%w: …", err)`.
- **Logging:** `zerolog` / `zap` for Go, structured JSON.
- **Comments:** focus on *why*, not *what*.

## Module structure

VertGuard has 5 modules delivered across 3 phases. Each module has:

- `internal/<module>/` — Go orchestration
- `rust/<module-specific-crate>/` — Rust performance-critical paths
- `python/ml_service/<module>/` — Python ML (Phase 4.2+)
- `docs/module-<N>-<name>.md` — module-specific docs

### Phase 4.1 modules (active)

- **Module 3: Prompt Injection Defence** — `internal/prompt/`,
  `rust/prompt-patterns/`, `docs/module-3-prompt-injection.md`
- **Module 4: AI Threat Intelligence Feed** — `internal/threatfeed/`,
  `docs/module-4-ai-threat-feed.md`
- **Module 1 (partial): C2PA verification** — `internal/media/`,
  `rust/c2pa/`, `docs/module-1-media-authenticity.md`

### Phase 4.2+ modules (stubs in place)

- Module 1 (ML deepfake detection): stub with `// TODO(phase-4.2)`
- Module 2 (AI Phishing): stub with `// TODO(phase-4.2)`
- Module 5 (Synthetic Identity): stub with `// TODO(phase-4.3)`

If you have ML expertise and want to start a stub module earlier,
open an issue with label `phase-4.2-claim` or `phase-4.3-claim`. The
core team will work with you on sequencing.

## Testing

| Command | Scope |
|---|---|
| `make test` | Unit tests only — fast, no Docker |
| `make test-integration` | Full suite including HTTP E2E against live Postgres |
| `make test-ml` | Python ML accuracy tests (requires ML dependencies) |
| `make test-fp` | False-positive regression suite |
| `make lint` | `golangci-lint run ./...` + `cargo clippy` |

Key conventions:

- Integration tests use `-p 1` (matches IRFlow's pattern — `TRUNCATE`
  parallelism issue).
- False-positive tests are **hard-required** for any detection code:
  every new detection rule ships with matching `tests/fp/` cases.
- ML tests skip cleanly when ML dependencies are absent (see
  `pytest.ini` markers).

## Dataset and model handling

**Never commit datasets or models.** Datasets can carry licensing
restrictions (CelebA, FaceForensics++, etc.); models are large and
their integrity is verified at runtime.

- Add dataset references to `datasets/datasets.yaml` with SHA-256
  checksums and source URL.
- Add model references to `models/models.yaml` with SHA-256 checksums
  and source.
- `download.sh` scripts in both directories fetch and verify.

If a dataset's licence prohibits even referencing it, don't reference
it — use a different dataset.

## Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(prompt): add 5 new jailbreak patterns from OWASP LLM Top 10

Adds patterns for variant prompt injections observed in production
deployments. See rust/prompt-patterns/src/jailbreak.rs.

Closes #123
```

Common scopes: `prompt`, `threatfeed`, `media`, `phishing`, `identity`,
`api`, `db`, `rust/c2pa`, `rust/prompt-patterns`, `python/ml`.

## Pull request checklist

- [ ] `make test` and `make lint` pass locally.
- [ ] `make test-integration` passes (or explain why it is not affected).
- [ ] `make test-fp` passes — **required** for any detection-related change.
- [ ] New detection patterns: matching false-positive test cases added.
- [ ] CHANGELOG.md `[Unreleased]` section updated.
- [ ] ADR filed under `../adrs/` if decision surface is new.
- [ ] Model or dataset additions: entries in `models/models.yaml` or
      `datasets/datasets.yaml` with verified checksums.
- [ ] CITADEL integration changes: schema compatibility verified against
      current Kerkese spec.

## Security-sensitive changes

Per [CODEOWNERS](../.github/CODEOWNERS), these paths require
security-team review:

- `internal/media/` — provenance verification logic
- `internal/prompt/` — pattern matching that enforces security policy
- `rust/c2pa/` — cryptographic verification
- `rust/prompt-patterns/` — security-enforcing logic
- `SECURITY.md`

## Reporting security issues

Never open a public issue for a VertGuard vulnerability. See
[SECURITY.md](SECURITY.md).

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Release flow

VertGuard follows the ecosystem release process. See
[../docs/release-process.md](../docs/release-process.md).

Versions follow semver:

- `vertguard/v0.1.0` — first alpha (Phase 4.1 modules, no ML)
- `vertguard/v0.5.0` — beta with ML layer (Phase 4.2 complete)
- `vertguard/v1.0.0` — stable, NIS3-ready (Phase 4.3 complete)

## Related

- [RFC-0004](../rfcs/RFC-0004-vertguard-platform.md) — open comment period
- [ADR-010](../adrs/ADR-010-vertguard-platform-strategy.md) — platform strategy
- Root [CONTRIBUTING.md](../CONTRIBUTING.md)
