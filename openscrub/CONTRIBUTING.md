# Contributing to OpenScrub

OpenScrub is the DDoS mitigation platform in the opensecstack
ecosystem — XDP/eBPF data plane (C + Rust/Aya), Go control-plane API
on `:8087`, React operator dashboard. Contributions are welcome, with
the kernel attack surface getting the highest review bar.

## Licence

OpenScrub is **Apache-2.0**. Contributions are licensed under the
same terms. See [LICENSE](LICENSE). The permissive licence is
deliberate — OpenScrub is a tool platform that can be embedded in
proprietary edge stacks. The audit-grade core (CITADEL, VertGuard)
is AGPL; OpenScrub produces evidence that flows into it.

## Where help is most welcome

| Area | What | Skill |
|---|---|---|
| eBPF / XDP data plane | LPM trie, rate-limit map, SYN-cookie path, CO-RE for older kernels | C, kernel BPF |
| Rust loader | Aya-based map management, Unix-socket control protocol | Rust |
| Go API | Endpoints, ThreatFlow puller, CITADEL emitter, rule TTL sweeper | Go (chi, pgx) |
| Dashboard | Routes, i18n (sq + en), accessibility | React + TS + Vite |
| Helm chart | Multi-NIC, hardened security context | Kubernetes |
| Threat-model | STRIDE additions, kernel-CVE tracking | Security review |
| Tests | hping3 / pktgen harness, kernel-version matrix | Bash, Go |

## The three zones

OpenScrub is split into three review zones — the same split used by
the agent group that built v1.0.0. Each zone has its own review
expectations:

- **Data plane** — [`ebpf/`](ebpf/) (C/eBPF) and
  [`rust/dataplane/`](rust/dataplane/) (Rust/Aya loader and
  `MapWriter` API). Kernel-attack-surface zone. All changes need
  security-team review and the live-kernel test suite green on the
  minimum supported kernel.
- **Go control plane** — [`cmd/openscrub/`](cmd/openscrub/),
  [`internal/`](internal/), [`api/openapi.yaml`](api/openapi.yaml),
  [`migrations/`](migrations/). Stateless replicas behind the LB.
  OpenAPI contract is the source of truth for clients.
- **Web** — [`web/`](web/). React + Vite SPA, served by nginx
  in production, talking to the API at `VITE_API_BASE_URL`.

A PR that touches more than one zone is fine — call it out in the
description so the right reviewers get pinged.

## Development setup

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/openscrub

cp .env.example .env
# Required: OPENSCRUB_DB_PASSWORD, OPENSCRUB_JWT_SECRET (>=32 bytes),
# OPENSCRUB_IFACE. CITADEL + ThreatFlow vars are optional in dev.

make build                # eBPF object + Rust loader + Go API + web
make test                 # unit tests across all three zones
make compose-up           # full stack on Docker Compose
curl http://localhost:8087/api/v1/health
```

For dashboard-only iteration:

```bash
cd web
npm ci
npm run dev               # Vite dev server, proxies /api to :8087
```

For Go-API-only iteration (no kernel needed — the data plane runs in
`noop` transport mode and writes to an in-memory shadow map):

```bash
OPENSCRUB_DATAPLANE_TRANSPORT=noop \
OPENSCRUB_DEV_MODE=true \
go run ./cmd/openscrub
```

## Required tools

- **Go 1.24+** — control plane.
- **Rust 1.75+** — loader and `MapWriter` library
  ([`rust/dataplane/`](rust/dataplane/)).
- **clang 14+** and **libbpf-dev** — for compiling
  [`ebpf/openscrub.bpf.c`](ebpf/openscrub.bpf.c). Linux only;
  non-Linux hosts can still build the Rust crate (it returns
  `UnsupportedPlatform` from `attach()`).
- **Node 20+** — React dashboard.
- **Docker + Docker Compose** — local stack and integration tests.
- **`golangci-lint`**, **`cargo clippy`**, **`eslint`** — `make lint`
  runs all three.

## Building the BPF object

The eBPF/C program lives in [`ebpf/`](ebpf/) and builds to
`ebpf/openscrub.bpf.o`. Both the Rust loader and the live-kernel
integration tests load it from there.

```bash
make -C ebpf              # produces ebpf/openscrub.bpf.o
```

`make build` does this for you. If you change the C struct layout,
update the `#[repr(C)]` mirrors in
[`rust/dataplane/src/loader_linux.rs`](rust/dataplane/src/loader_linux.rs)
in the same PR — `LpmV4Key`, `LpmV6Key`, `RatelimitValue` must stay
in lock-step with the C definitions or the loader will silently write
garbage into BPF maps.

## Running the integration tests

| Command | Scope | Privileges |
|---|---|---|
| `make test` | Unit tests across Go, Rust, web | None |
| `cargo test` (in [`rust/dataplane/`](rust/dataplane/)) | Rust unit + offline integration | None |
| `sudo cargo test -- --ignored` | Live-kernel attach to loopback | Linux + `CAP_BPF` + `CAP_NET_ADMIN` + compiled `openscrub.bpf.o` |
| `go test -tags=integration ./tests/integration/...` | API contract tests against a running stack | Stack already up |
| `make test-integration` | End-to-end: brings up compose, fires `hping3`, asserts drop counter | Docker + privileged loader container |

The Rust live-kernel tests are gated behind `#[ignore]` so a fresh
`cargo test` stays green on developer laptops. Run them with
`--ignored` whenever you change the loader or the map schema. CI
runs them on the kernel matrix.

## Kernel compatibility

OpenScrub's hard floor is **Linux 5.15** (the loader refuses to start
on older kernels — see
[docs/troubleshooting.md § "kernel too old"](docs/troubleshooting.md)).
Any kernel-touching change must compile against 5.15 with CO-RE; if a
feature legitimately needs a newer kernel, gate it on a feature probe
and fall back gracefully. Bumping the floor is an ADR-level decision,
not a PR-level one.

The recommended kernel is 6.1 LTS or newer.

## Adding a new rule type

The current types are `blocklist`, `ratelimit`, `syncookie` (see
[`internal/rules/rule.go`](internal/rules/rule.go)). To add a fourth:

1. Extend the `Type` enum and validation in
   [`internal/rules/rule.go`](internal/rules/rule.go).
2. Add the corresponding BPF map (or extend an existing one) in
   [`ebpf/openscrub.bpf.c`](ebpf/openscrub.bpf.c) and mirror the
   key/value structs in
   [`rust/dataplane/src/loader_linux.rs`](rust/dataplane/src/loader_linux.rs).
3. Extend the `MapWriter` API in
   [`rust/dataplane/src/maps.rs`](rust/dataplane/src/maps.rs) and the
   Unix-socket control protocol consumed by
   [`internal/dataplane/`](internal/dataplane/).
4. Update [`api/openapi.yaml`](api/openapi.yaml) — the `Rule` and
   `CreateRuleRequest` enums.
5. Update [`docs/api.md`](docs/api.md) and
   [`docs/configuration.md`](docs/configuration.md) if config
   surfaces.
6. Add a Prometheus label value to
   [`internal/metrics/metrics.go`](internal/metrics/metrics.go) so
   `openscrub_rules_total{type="…"}` reports it.
7. Add a contract test in
   [`tests/integration/api_contract_test.go`](tests/integration/api_contract_test.go).

A new rule type is a coordinated PR across all three zones; expect
data-plane and security review.

## Extending the Go API

New endpoints land in [`internal/api/`](internal/api/):

1. Define the request/response shapes and add the path to
   [`api/openapi.yaml`](api/openapi.yaml) **first** — the OpenAPI
   contract is the source of truth.
2. Wire the handler in `internal/api/router.go` (or the matching
   sub-package).
3. Use the existing `auth` middleware for anything that mutates state
   — see [`internal/auth/`](internal/auth/).
4. Add metrics via [`internal/metrics/`](internal/metrics/) — no new
   global registries; reuse `metrics.Registry`.
5. Add a contract test against the running stack under
   [`tests/integration/`](tests/integration/).

Avoid surface bloat: Prometheus PromQL is **not** proxied through
the API by design ([docs/api.md](docs/api.md) explains why). Keep
the surface small, the threat model small.

## Code style

- **Go:** `gofmt` + `goimports`, `golangci-lint run ./...`. Errors
  return, do not panic. Wrap with `fmt.Errorf("%w: …", err)`.
  Logging via `zerolog`, structured JSON.
- **Rust:** `cargo fmt` + `cargo clippy -- -D warnings`. No `unwrap`
  on the loader-attach path; map errors into `DataplaneError`.
- **C/eBPF:** keep functions small; the verifier rejects anything
  too clever. Comment every map definition.
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
feat(rules): add syncookie TTL sweeper

Closes #123
```

Common scopes: `ebpf`, `loader`, `api`, `rules`, `ioc`, `citadel`,
`auth`, `web`, `helm`, `docs`.

## Pull request checklist

- [ ] `make test` and `make lint` pass locally.
- [ ] Data-plane changes: live-kernel tests pass
      (`sudo cargo test -- --ignored`).
- [ ] Kernel-touching changes compile against the 5.15 floor.
- [ ] OpenAPI contract updated alongside any API surface change.
- [ ] [CHANGELOG.md](CHANGELOG.md) `[Unreleased]` section updated.
- [ ] Commits DCO-signed (`-s`).
- [ ] Security-team review requested for any
      `ebpf/`, `rust/dataplane/`, `internal/auth/`, or
      `internal/citadel/` change.

## Reporting security issues

Never open a public issue for an OpenScrub vulnerability — especially
for kernel-escape, BPF-verifier-bypass, loader-privilege-escalation,
or rule-injection findings. See [SECURITY.md](SECURITY.md). Kernel-
escape disclosures from external researchers are routed directly to
the core security team and treated as critical-severity by default.

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Related

- [README.md](README.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/security/threat-model.md](docs/security/threat-model.md)
- [docs/operator-handbook.md](docs/operator-handbook.md)
- [SECURITY.md](SECURITY.md)
- [ROADMAP.md](ROADMAP.md)
