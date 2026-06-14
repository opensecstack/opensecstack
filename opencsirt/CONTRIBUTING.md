# Contributing to OpenCSIRT

OpenCSIRT is the national/sector CSIRT operations platform in the
opensecstack ecosystem — Go API on `:8088`, Python advisory subsystem
on `:8089`, React operator dashboard on `:3088`. Contributions are
welcome, with the auth layer, CITADEL outbox, and peer handshake
getting the highest review bar.

## Licence

OpenCSIRT is **AGPL-3.0-or-later**. Contributions are licensed under
the same terms. See [LICENSE](LICENSE). The copyleft is deliberate —
OpenCSIRT is a governance-tier platform; modifications run as a
network service must be made available to users of that service per
AGPL § 13. Same licence as CITADEL, VertGuard, IRFlow.

## Where help is most welcome

| Area | What | Skill |
|---|---|---|
| Go API | Endpoints, integrations, CITADEL outbox, peer handshake | Go (chi, pgx) |
| Python advisory | CSAF 2.0 templates, schema validation, multi-language `note` blocks | Python 3.11, FastAPI |
| Dashboard | Incidents board, advisory editor, peer roster, accessibility | React + TS + Vite |
| Helm chart | Production hardening, network policies | Kubernetes |
| Threat model | STRIDE additions on the peer handshake, TLP enforcement | Security review |
| Tests | Integration matrix across Go + Python + Postgres | Bash, Go, pytest |

## The three zones

OpenCSIRT is split into three review zones — the same split used by
the agent group that built v1.0.0. Each zone has its own review
expectations:

- **Go core** — [`cmd/opencsirt/`](cmd/opencsirt/),
  [`internal/`](internal/), [`api/openapi.yaml`](api/openapi.yaml),
  [`migrations/`](migrations/). Stateless replicas behind the LB.
  OpenAPI contract is the source of truth for clients.
- **Python advisory** — [`python/`](python/). FastAPI service,
  CSAF 2.0 generation/validation. Stateless. Talks to nothing but
  the Go core.
- **Web** — [`web/`](web/). React + Vite SPA, served by nginx
  in production, talking to the API at `VITE_API_BASE_URL`.

A PR that touches more than one zone is fine — call it out in the
description so the right reviewers get pinged. Auth, CITADEL, peer
handshake, and TLP-enforcement changes additionally require a
security-team review regardless of zone.

## Development setup

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/opencsirt

cp .env.example .env
# Required for `make dev`:
#   OPENCSIRT_JWT_SECRET             (>=32 bytes — `openssl rand -base64 32`)
#   OPENCSIRT_PASSWORD_PEPPER        (>=32 bytes from CSPRNG)
#   OPENCSIRT_USERS                  (at least one operator entry)
# Optional in dev — leave empty to disable:
#   OPENCSIRT_CITADEL_*              (CITADEL dry-run defaults true)
#   OPENCSIRT_THREATFLOW_API_URL     (IOC ingest)
#   OPENCSIRT_IRFLOW_WEBHOOK_SECRET  (IRFlow webhook auth)
#   OPENCSIRT_NIS2COMPASS_API_URL    (NIS2 push)
#   OPENCSIRT_VERTGUARD_API_URL      (CVE subscriber)

make build                # Go API + Python wheel + web
make test                 # unit tests across all three zones
make dev                  # docker compose up
curl http://localhost:8088/api/v1/health
```

For dashboard-only iteration:

```bash
cd web
npm ci
npm run dev               # Vite dev server on :3088, proxies /api to :8088
```

For Go-API-only iteration (no Python subsystem needed — the advisory
client falls back to NoopClient):

```bash
OPENCSIRT_DEV_MODE=true \
OPENCSIRT_ADVISORY_SERVICE_URL= \
go run ./cmd/opencsirt
```

For Python-only iteration:

```bash
cd python
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
uvicorn advisory.app:app --reload --port 8089
```

## Required tools

- **Go 1.22+** — Go core.
- **Python 3.11+** — advisory subsystem.
- **Node 20+** — React dashboard.
- **PostgreSQL 16** — persistence (compose brings it up).
- **Docker + Docker Compose** — local stack and integration tests.
- **`golangci-lint`**, **`ruff`**, **`eslint`** — `make lint` runs
  all three.

## Running the integration tests

| Command | Scope | Prerequisites |
|---|---|---|
| `make test` | Unit tests across Go, Python, web | None |
| `make test-postgres` | Go integration suite against a live Postgres | `OPENCSIRT_TEST_DB_URL` set |
| `bash tests/integration/run.sh` | End-to-end: brings up compose, seeds an incident, drafts and publishes an advisory, asserts CITADEL outbox row | Docker |
| `pytest python/tests` | Python advisory subsystem | `pip install -e python[dev]` |

The Go-side integration tests follow the OpenScrub / IRFlow pattern:
they `t.Skip()` silently when `OPENCSIRT_TEST_DB_URL` is unset so a
fresh `go test ./...` stays green on developer laptops.

## Extending the Go API

New endpoints land in [`internal/api/`](internal/api/):

1. Define the request/response shapes and add the path to
   [`api/openapi.yaml`](api/openapi.yaml) **first** — the OpenAPI
   contract is the source of truth.
2. Wire the handler in `internal/api/router.go` (or the matching
   sub-package).
3. Use the existing `auth` middleware for anything that mutates state
   — see [`internal/auth/auth.go`](internal/auth/auth.go). Pick the
   *minimum* role that should be allowed; the six-role ladder is
   `viewer < external_peer < analyst < operator < csirt_lead < admin`.
4. Add metrics via [`internal/metrics/metrics.go`](internal/metrics/metrics.go)
   — no new global registries; reuse `metrics.Registry`.
5. Add a contract test under [`tests/`](tests/).

Avoid surface bloat: the API is a CSIRT operations console, not a
SIEM and not a ticket system. Keep endpoints small; route bulk data
through the existing pagination contract.

## Adding a new integration

The integrations live in [`internal/integrations/`](internal/integrations/).
A new outbound integration (e.g. a second NIS2 reporting target):

1. Add the env-var name to
   [`internal/config/config.go`](internal/config/config.go) and
   document it in [`.env.example`](.env.example).
2. Implement the client in `internal/integrations/<name>/`.
3. Wire it into the appropriate event hook
   (`incident_opened`, `advisory_published`, …).
4. Add a Prometheus counter labelled by outcome.
5. Document the wire format and failure modes in
   [`docs/`](docs/) — one `<name>-integration.md` per integration.

## Code style

- **Go:** `gofmt` + `goimports`, `golangci-lint run ./...`. Errors
  return, do not panic. Wrap with `fmt.Errorf("%w: …", err)`.
  Logging via `zerolog`, structured JSON. **Never log incident
  bodies, advisory plaintext, or peer-CSIRT identifiers.** Log row
  ids only.
- **Python:** `ruff format` + `ruff check`. Pydantic v2 for request
  models. Fail closed on schema validation.
- **TypeScript / React:** `prettier` + `eslint`, strict TS
  (`noImplicitAny`, `strict: true`).
- **Comments:** focus on *why*, not *what*.

## DCO sign-off

Every commit must be signed off:

```
git commit -s -m "your message"
```

This adds a `Signed-off-by:` trailer asserting the
[Developer Certificate of Origin](https://developercertificate.org/).
PRs without DCO sign-off are blocked by CI.

## Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(advisory): add multi-language note rendering

Closes #123
```

Common scopes: `api`, `incident`, `advisory`, `auth`, `citadel`,
`peer`, `threatflow`, `irflow`, `nis2`, `vertguard`, `web`, `python`,
`helm`, `docs`.

## Pull request checklist

- [ ] `make test` and `make lint` pass locally.
- [ ] OpenAPI contract updated alongside any API surface change.
- [ ] Migrations are forward-compatible; rollback is `migrations/<n>.down.sql`.
- [ ] [CHANGELOG.md](CHANGELOG.md) `[Unreleased]` section updated.
- [ ] Commits DCO-signed (`-s`).
- [ ] Security-team review requested for any
      `internal/auth/`, `internal/citadel/`, peer-handshake, or
      TLP-enforcement change.

## Reporting security issues

Never open a public issue for an OpenCSIRT vulnerability — especially
for incident-data-leak, advisory-tampering, CITADEL-HMAC-bypass,
JWT-forgery, or webhook-spoofing findings. See [SECURITY.md](SECURITY.md).
**There is no kernel attack surface in OpenCSIRT** — the kernel-escape
disclosure tier from OpenScrub does not apply here. **What does apply
is incident-data confidentiality**: any finding that lets a non-CSIRT
party read an incident row, a peer-CSIRT identifier, or a TLP:RED
advisory is treated as critical-severity by default.

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Related

- [README.md](README.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/operator-handbook.md](docs/operator-handbook.md)
- [docs/peer-csirt-handshake-protocol.md](docs/peer-csirt-handshake-protocol.md)
- [SECURITY.md](SECURITY.md)
- [ROADMAP.md](ROADMAP.md)
