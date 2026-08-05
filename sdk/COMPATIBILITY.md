# SDK Compatibility Matrix

This file is the compatibility matrix mandated by
[ADR-003: SemVer with platform compatibility matrix](adrs/003-semver-with-platform-matrix.md).
It maps each SDK package/version to the platform API version(s) it supports,
and is updated on every SDK release.

## How we version this (summary of ADR-003)

- The SDK follows [SemVer](https://semver.org/).
- A breaking platform API change forces an SDK **major** version bump.
- A deprecated platform API version stays supported for one additional SDK
  major version after the platform removes it.
- This matrix must be updated alongside every SDK release — see the ADR for
  full rationale.

## Important: the SDK is not one version number

There is no single "SDK version." The SDK ships as **eight independently
versioned packages** across four languages. In particular, the Go SDK is
**four separate Go modules**, each tagged and released on its own schedule
(see [`sdk/go/RELEASING.md`](go/RELEASING.md) for the `sdk/go/vX.Y.Z`-style
tag convention):

| Package | Language | Module / package name | Current version | Released? |
|---|---|---|---|---|
| Core client | Go | `github.com/opensecstack/sdk` (`sdk/go/opensecstack`) | 1.0.0 (per [CHANGELOG.md](CHANGELOG.md)) | Yes, but **no `sdk/go/vX.Y.Z` git tag exists in this repo yet** — consumers currently track repo HEAD via `go get github.com/opensecstack/sdk@<commit>`, not a tagged module version |
| Core client | Python | `opensecstack-sdk` | 1.0.0 (`pyproject.toml`) | Yes |
| Core client | TypeScript | `@opensecstack/sdk` | 1.0.0 (`package.json`) | Yes |
| Core client | Rust | `opensecstack` | 1.0.0 (`Cargo.toml`) | Yes |
| `password` hasher | Go | `github.com/opensecstack/sdk/password` (separate module, own `go.mod`) | untagged — added post-1.0.0, currently under `[Unreleased]` in CHANGELOG.md | No |
| `password` hasher | Python | `opensecstack-password` | 1.0.0 (`pyproject.toml`) | Listed as `[Unreleased]` in CHANGELOG.md — not yet part of a tagged SDK release |
| `sinauth` OIDC/JWT client | Go | `github.com/opensecstack/sdk/go/sinauth` (separate module, own `go.mod`) | untagged | No |
| `sinauth` OIDC/JWT client | TypeScript | `@opensecstack/sinauth` | 0.1.0 (`package.json`) | No |
| `citadel` MARSHAL client | Go | `github.com/opensecstack/sdk/go/citadel` (separate module, own `go.mod`) | untagged, newest of all packages | No |

Rust and Python have no `sinauth`, `citadel` MARSHAL, or standalone
`password`/companion packages yet — see [README.md](README.md#whats-inside)
for the full per-language feature matrix.

## Compatibility matrix

### Core client (APIGuard / NIS2 Compass / CITADEL event connector) — Go, Python, TypeScript, Rust, all v1.0.0

The four core-client packages were released together and target the same
platform API contracts (per CHANGELOG.md `[1.0.0] — 2026-04-08`: "All
platform client references updated from v0.1.x to v1.0.0 API contracts").
There is no compatibility-breaking history yet — this is the SDK's first
generation.

| SDK package @ version | APIGuard API | NIS2 Compass API | CITADEL event/WORM API |
|---|---|---|---|
| Go core client 1.0.0 | v1.0.0 | v1.0.0 | v1.0.0 |
| Python `opensecstack-sdk` 1.0.0 | v1.0.0 | v1.0.0 | v1.0.0 |
| TypeScript `@opensecstack/sdk` 1.0.0 | v1.0.0 | v1.0.0 | v1.0.0 |
| Rust `opensecstack` 1.0.0 | v1.0.0 | v1.0.0 | v1.0.0 |
| (all, prior) 0.1.0 | v0.1.x | v0.1.x | n/a (CITADEL connector introduced in 1.0.0-era work) |

Per ADR-003, deprecated platform API versions remain supported for one SDK
major version after removal. Since no platform has removed a v0.x/v1.x API
version yet, no deprecation window is currently active.

### `password` hasher (Go, Python) — cross-language format compatibility, not yet a tagged SDK release

| Package | Version | Wire format | Compatible with |
|---|---|---|---|
| Go `sdk/go/password` | untagged (`[Unreleased]`) | Argon2id (RFC 9106) + HMAC-SHA256 pepper, PHC string encoding | Byte-compatible with `opensecstack-password` (Python) — hashes produced by either verify on the other |
| Python `opensecstack-password` | 1.0.0 | same PHC format as above | Byte-compatible with Go `sdk/go/password` |

No platform API version applies here — this package hashes secrets locally
and does not call a platform HTTP API. First adopter: IRFlow
(`auth.Config.Pepper` / `auth.NewHasher`).

### `sinauth` OIDC/JWT client (Go, TypeScript) — not yet tagged

| Package | Version | Verifies tokens issued by |
|---|---|---|
| Go `sdk/go/sinauth` | untagged | sinauth (RS256, OIDC discovery + JWKS) |
| TypeScript `@opensecstack/sinauth` | 0.1.0 | sinauth (RS256, OIDC discovery + JWKS) |

**Known gap:** [`ECOSYSTEM.md`](../ECOSYSTEM.md) and the root
[`README.md`](../README.md) list sinauth itself as **v1.0.0, Production**,
but `sinauth/CHANGELOG.md` has never recorded a `[1.0.0]` release entry —
every change is still listed under `[Unreleased]`. Until that's reconciled,
treat "sinauth v1.0.0" in this matrix as the ecosystem-level platform
version these clients target, not confirmation of a tagged sinauth release.

### `citadel` MARSHAL client (Go only) — not yet tagged

| Package | Version | Kerkese wire format | Targets |
|---|---|---|---|
| Go `sdk/go/citadel` | untagged, newest package in the SDK | `kerkese_version: "1.0"` (see `types.go`, `sign_test.go`) | CITADEL MARSHAL evaluation engine v1.0.0 |

Not yet ported to Python, TypeScript, or Rust.

## Platform API versions referenced above

All confirmed from each platform's own `CHANGELOG.md` and cross-checked
against the root [`ECOSYSTEM.md`](../ECOSYSTEM.md) (as of its
2026-05-23, ecosystem v1.2.0 status line):

| Platform | Current API version |
|---|---|
| APIGuard | v1.0.0 |
| NIS2 Compass | v1.0.0 |
| CITADEL | v1.0.0 |
| IRFlow | v1.0.0 |
| ThreatFlow | v1.0.0 |
| OpenScrub | v1.0.0 |
| CyberPath | v1.0.0 |
| SecureLab | v1.0.0 |
| OpenCSIRT | v1.0.0 |
| VertGuard | v1.0.0 (partial functionality — see ECOSYSTEM.md's Known Gaps: 2 of 5 modules still return `501`) |
| sinauth | v1.0.0 per ECOSYSTEM.md/README.md — see the "Known gap" note above, its own CHANGELOG.md has not recorded a matching `[1.0.0]` entry |

## See also

- [ADR-003: SemVer with platform compatibility matrix](adrs/003-semver-with-platform-matrix.md) — the policy this file implements
- [CHANGELOG.md](CHANGELOG.md) — SDK release history
- [docs/migration.md](docs/migration.md) — breaking-change upgrade instructions per release
- [README.md](README.md) — full per-language feature matrix and package list
