# Contributing to CyberPath

CyberPath is the security training and certification platform in the
opensecstack ecosystem. Contributions are welcome — especially track
content authoring, lab image work, and the Wasm sandbox runtime.

## Licence

CyberPath is **Apache 2.0**. Contributions are licensed under the
same terms. See [LICENSE](LICENSE).

CyberPath is a tool platform — it can be embedded in proprietary
training pipelines and corporate LMS deployments. The permissive
licence is deliberate.

## Development setup

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/cyberpath

# Copy the example env (lands with v0.0.1)
cp .env.example .env

# Start the integration test Postgres
docker compose -f docker-compose.test.yml up -d postgres

# Build + run unit tests
make build
make test
```

## Required tools

- Go 1.24+
- Node 20+ (for the React frontend)
- Rust 1.75+ (for the Wasm sandbox runtime, v1.0.0 onwards)
- Docker + Docker Compose
- `golangci-lint` (for `make lint`)
- `wasmtime` CLI (only if working on Wasm lab images)

## Code style

- **Go:** `gofmt` + `goimports`, enforced by `.golangci.yml` (same
  config as other platforms in the ecosystem).
- **TypeScript / React:** `prettier` + `eslint`, strict TS
  (`noImplicitAny`, `strict: true`).
- **Rust:** `rustfmt` + `clippy` at `deny(warnings)` level.
- **Errors:** return, don't panic. Wrap with `fmt.Errorf("%w: …", err)`.
- **Logging:** `zerolog` for Go, structured JSON.
- **Comments:** focus on *why*, not *what*.

## Module structure (post-v0.0.1)

CyberPath has 8 logical modules across two releases. Each module
has:

- `internal/<module>/` — Go orchestration
- `web/src/<module>/` — React UI surface (where applicable)
- `rust/<crate>/` — Rust crates (Wasm sandbox runtime, v1.0.0+)
- `docs/<module>.md` — module-specific docs

### v1.0.0 modules (Phase 2 first cut)

- **Module 1: Learning Path Engine** — `internal/path/`,
  `web/src/learner/`, `docs/module-1-learning-path.md`
- **Module 2: Quiz & Assessment Engine** — `internal/quiz/`,
  `web/src/quiz/`, `docs/module-2-quiz.md`
- **Module 3: Docker-Based Labs** — `internal/lab/docker/`,
  `web/src/terminal/`, `docs/module-3-docker-labs.md`

### v1.0.0 modules

- **Module 4: Wasm Sandbox Labs** — `internal/lab/wasm/`,
  `rust/lab-runtime/`, `docs/module-4-wasm-labs.md`
- **Module 5: Certification Issuance** — `internal/cert/`,
  `docs/module-5-certification.md`
- **Module 6: CITADEL Evidence Emitter** — `internal/citadel/`,
  `docs/citadel-integration.md`
- **Module 7: NIS2 Compass Coverage API** — `internal/coverage/`,
  `docs/nis2-integration.md`
- **Module 8: Content Versioning** — `internal/content/`,
  `docs/module-8-content-versioning.md`

## Track content contributions

Track content (lessons, quizzes, lab exercises) is the largest
contribution surface. Each track lives under
`content/<track-slug>/` and includes:

- `track.yaml` — metadata (id, title, audience, NIS2 mapping,
  prerequisites, duration, certification: yes/no)
- `lessons/*.md` — lesson markdown bilingual (`*.sq.md`, `*.en.md`)
- `quizzes/*.yaml` — question banks
- `labs/*.yaml` — lab definitions referencing a lab image

Track content review checklist:

- [ ] NIS2 Article 21 measure mapping documented in `track.yaml`
- [ ] Bilingual: shqip + anglisht present for every lesson
- [ ] Quiz questions reviewed by at least one subject-matter peer
- [ ] Lab exercises reproducible from the published lab image
- [ ] `track.yaml` lists prerequisites and estimated duration
- [ ] No copyrighted content reused without attribution

## Testing

| Command | Scope |
|---|---|
| `make test` | Unit tests only — fast, no Docker |
| `make test-integration` | Full suite including HTTP E2E against live Postgres |
| `make test-content` | Content lint (track.yaml validation, lesson bilingual coverage) |
| `make test-sandbox` | Sandbox isolation tests (v1.0.0+) |
| `make lint` | `golangci-lint run ./...` + `cargo clippy` + `eslint` |

Key conventions:

- Integration tests use `-p 1` (matches the ecosystem pattern —
  shared Postgres `TRUNCATE` parallelism issue).
- Sandbox isolation tests are **hard-required** for any change to
  the Wasm runtime.

## Lab image handling

**Never commit lab image binaries.** Lab images are large and their
integrity is verified at runtime.

- Add lab image references to `labs/labs.yaml` with SHA-256
  checksums and source URL.
- `download.sh` fetches and verifies.
- Lab images that ship a kernel or full userspace go through extra
  review — see SECURITY.md.

## Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(path): add prerequisite resolution for nested tracks

Resolves multi-level prerequisite graphs without recursion limits.
See internal/path/prereq.go.

Closes #42
```

Common scopes: `path`, `quiz`, `lab`, `cert`, `citadel`, `coverage`,
`content`, `web`, `rust/lab-runtime`, `api`, `db`.

## Pull request checklist

- [ ] `make test` and `make lint` pass locally.
- [ ] `make test-integration` passes (or explain why it is not
      affected).
- [ ] CHANGELOG.md `[Unreleased]` section updated.
- [ ] ADR filed under `../adrs/` if a new decision surface is
      introduced.
- [ ] Track content additions: bilingual coverage verified, NIS2
      mapping documented.
- [ ] Sandbox-runtime changes: isolation tests pass; security-team
      review requested.
- [ ] CITADEL integration changes: schema compatibility verified
      against current Kerkese spec.

## Security-sensitive changes

These paths require security-team review:

- `internal/lab/wasm/` — sandbox host
- `rust/lab-runtime/` — Wasm runtime + isolation policy
- `internal/cert/` — signing key handling
- `internal/citadel/` — evidence emitter
- `SECURITY.md`

## Reporting security issues

Never open a public issue for a CyberPath vulnerability — especially
for Wasm sandbox escapes. See [SECURITY.md](SECURITY.md).

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Release flow

CyberPath follows the ecosystem release process. See
[../docs/release-process.md](../docs/release-process.md).

Versions follow semver:

- `cyberpath/v0.0.1` — first scaffold + skeleton code
- `cyberpath/v1.0.0` — first alpha (Modules 1, 2, 3)
- `cyberpath/v1.0.0` — stable, NIS2 Article 21(2)(g) evidence-grade

## Related

- [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md) — platform strategy
- Root [CONTRIBUTING.md](../CONTRIBUTING.md)
