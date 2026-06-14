# c2pa-verify

Thin Rust CLI wrapper around [`c2pa-rs`](https://crates.io/crates/c2pa)
that VertGuard's Go service shells out to for real C2PA manifest
verification (Phase 4.2 / VG-011-c). Output is a stable JSON shape
consumed by `internal/media.Result` on the Go side.

## Build status

**Linux-only build for now.** MinGW-w64 link failures with
`openssl-sys` are a known limitation — `c2pa = "0.30"` with the
`openssl_sign` feature pulls in a native OpenSSL dep tree that does
not link cleanly under mingw-w64 on Windows hosts. Linux with
`libssl-dev` + `pkg-config` works and is what CI exercises (see the
`c2pa-verify` job in `.github/workflows/ci.yml`).

If you need to develop on Windows, options are:

- WSL2 with `apt-get install libssl-dev pkg-config build-essential`
  (recommended; matches CI exactly).
- A Linux dev container.
- MSVC toolchain + vcpkg openssl (untested here; PRs welcome).

Native MinGW support is **deferred** until upstream `c2pa-rs` ships
a `rustls`-only build path that we can switch to. Track this against
VG-011-c in `docs/security/pre-audit-plan.md`.

## Build

```bash
# Debian/Ubuntu host:
sudo apt-get install -y libssl-dev pkg-config build-essential
cargo build --release --manifest-path rust/c2pa-verify/Cargo.toml
```

The resulting binary lands at
`rust/target/release/c2pa-verify` (workspace target dir).

## Test

```bash
cargo test --manifest-path rust/c2pa-verify/Cargo.toml
```

Integration tests live in `tests/integration_test.rs`.

## Versioning

`c2pa-rs` is pinned at **0.30** with `default-features = false` plus
`["openssl_sign", "file_io"]`. Rationale:

- The `Reader::from_file` / `validation_status` API surface we use
  is stable across the 0.30 → 0.49 range, so we get a smaller dep
  tree without losing functionality.
- Bumping to 0.49+ is tracked in `Cargo.toml` as a TODO for after
  Phase 4.2.1, alongside the upstream trust-list integration story.

If 0.30 turns out to have a Linux build regression we can't work
around, the next known-good versions to try are 0.36 and 0.49.
**Assumption:** 0.30 still builds clean on `ubuntu-latest` with
the system deps listed above; if CI proves otherwise, bump and
record the working version here.
