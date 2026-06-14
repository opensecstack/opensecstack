# c2pa-verify Deployment

How to provision the `c2pa-verify` Rust binary
([`rust/c2pa-verify/`](../rust/c2pa-verify/)) in a production
VertGuard installation. The binary wraps
[`c2pa-rs`](https://crates.io/crates/c2pa) 0.30 and is the only
component VertGuard's Go service shells out to for cryptographic
manifest verification (Module 1 — Media Authenticity).

This doc focuses on **building, packaging and deploying** the
binary. For the trust-store contents and rotation cadence, see
[`c2pa-trust-store.md`](c2pa-trust-store.md). For the request-path
integration, see [`c2pa-integration.md`](c2pa-integration.md).

## Build matrix

| Platform | Status | Notes |
|---|---|---|
| Ubuntu 22.04 / 24.04 (`x86_64-unknown-linux-gnu`) | **Supported** | What CI builds — see the `c2pa-verify` job in `.github/workflows/ci.yml`. |
| Debian 12 / RHEL 9 with `libssl3` + `pkg-config` | Supported (community) | Same toolchain as Ubuntu; rebuild from source. |
| macOS (Apple Silicon, `aarch64-apple-darwin`) | Untested | Should work — `c2pa-rs` 0.30 with `openssl_sign` builds against system OpenSSL via Homebrew, but no CI coverage. |
| Windows MinGW (`x86_64-pc-windows-gnu`) | **Known broken** | `openssl-sys` link failure under mingw-w64. Documented in [`rust/c2pa-verify/README.md`](../rust/c2pa-verify/README.md). Use the prebuilt Linux binary inside a container, or build under WSL2. |
| Windows MSVC + vcpkg | Best-effort | Untested; PRs welcome. |

The supported production path is **Linux, built either from source
or distributed as a multi-stage container image** (see below).

## Build from source on Ubuntu

```bash
# 1. System deps. libssl-dev + pkg-config are required by openssl-sys.
sudo apt-get update
sudo apt-get install -y libssl-dev pkg-config build-essential

# 2. Stable Rust toolchain (rustup or distro package both work).
curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# 3. Build only the c2pa-verify crate (skips the rest of the workspace).
cd vertguard/rust
cargo build --release -p c2pa-verify

# 4. Output:
ls -lh target/release/c2pa-verify
# -rwxr-xr-x  ... target/release/c2pa-verify

# 5. Smoke run:
./target/release/c2pa-verify --help
./target/release/c2pa-verify --input ../../tests/fixtures/c2pa/signed.jpg \
    --format json
```

Strip the binary for production:

```bash
strip --strip-unneeded target/release/c2pa-verify
```

## Trust store provisioning

`c2pa-verify` needs a PEM bundle of trust anchors to validate
manifest signer chains. Without one it falls back to the
upstream embedded trust list, which is **demo-only** (see
[`c2pa-trust-store.md`](c2pa-trust-store.md) — production
deployments must supply their own bundle).

Production layout:

```
/etc/vertguard/trust-store/
├── bundle.pem        # public C2PA roots + your private signing CAs
└── README            # change-log + last rotation date
```

```bash
sudo install -d -o root -g vertguard -m 0750 /etc/vertguard/trust-store
sudo install -o root -g vertguard -m 0640 ./bundle.pem /etc/vertguard/trust-store/bundle.pem
```

Wire the path through:

```bash
# Local single-host (systemd unit env):
VERTGUARD_MEDIA_C2PA_TRUSTSTORE=/etc/vertguard/trust-store/bundle.pem
VERTGUARD_MEDIA_BINARY_PATH=/usr/local/bin/c2pa-verify
```

For Helm see the [Helm values](#helm-values) section.

## Container image

Multi-stage Dockerfile snippet for embedding `c2pa-verify` into the
runtime image (this is what `vertguard/Dockerfile` does for
production builds):

```dockerfile
# ---- Stage 1: build c2pa-verify on Debian slim with system OpenSSL ----
FROM rust:1.79-slim-bookworm AS c2pa-builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libssl-dev pkg-config build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust/ ./rust/
RUN cargo build --release --manifest-path rust/c2pa-verify/Cargo.toml \
 && strip --strip-unneeded rust/target/release/c2pa-verify

# ---- Stage 2: runtime ----
# distroless:nonroot-debian12 ships libssl3 + ca-certificates already.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=c2pa-builder /src/rust/target/release/c2pa-verify \
     /usr/local/bin/c2pa-verify
# ... copy the Go binary, entrypoint, etc.
```

Image-signing note: every release image is cosign-signed via GitHub
OIDC. Verify before pinning a digest — see
[`security/image-signing.md`](security/image-signing.md).

```bash
cosign verify ghcr.io/opensecstack/vertguard@sha256:<DIGEST_FROM_RELEASE> \
    --certificate-identity-regexp 'https://github.com/opensecstack/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Helm values

The Helm chart already exposes the relevant knobs in the parent
[`deploy/helm/vertguard/values.yaml`](../deploy/helm/vertguard/values.yaml)
under `config.media`:

```yaml
config:
  media:
    # Path to c2pa-verify inside the runtime image. Default Dockerfile
    # installs it at /usr/local/bin/c2pa-verify.
    binary_path: /usr/local/bin/c2pa-verify
    # Per-invocation timeout. Bump for large MP4s with many manifests.
    timeout: 10s
    # Trust anchors PEM bundle (mounted via ConfigMap or Secret).
    c2pa_truststore: /etc/vertguard/trust-store/bundle.pem
    c2pa_ocsp_enabled: false
    max_size: 104857600        # 100 MiB upload cap
    content_retention: false   # detection metadata only, never raw bytes
```

Mount the trust-store PEM via ConfigMap (public roots only) or
Secret (if it contains private CA material) — full pattern in
[`c2pa-trust-store.md`](c2pa-trust-store.md).

## Smoke test

Generate or fetch a signed test asset. The repo ships fixtures
under `vertguard/tests/fixtures/c2pa/` (signed and tampered
samples); operators without repo access can sign a JPEG with
`c2patool` from the upstream project.

```bash
# In-cluster:
kubectl -n vertguard exec deploy/vertguard -- \
    /usr/local/bin/c2pa-verify \
        --input /tmp/sample-signed.jpg \
        --format json \
        --trust-store /etc/vertguard/trust-store/bundle.pem | jq .

# Expected (truncated):
# {
#   "verdict": "AUTHENTIC",
#   "signer": { "common_name": "...", "issuer": "..." },
#   "validation_status": "valid",
#   "manifests": [ ... ]
# }
```

End-to-end via the public API (the response is logged to
`prompt_scans`/`media_scans` and a WORM entry is emitted — see
[`citadel-integration.md`](citadel-integration.md)):

```bash
curl -sS -X POST https://vertguard.example.com/api/v1/media/verify \
    -H "Authorization: Bearer ${VG_TOKEN}" \
    -F 'file=@./sample-signed.jpg' | jq .
# Expect classification == "AUTHENTIC" and worm_entry_id populated.
```

A tampered asset must come back as `UNAUTHENTIC` with a
non-empty `validation_status`. If the signed asset returns
`UNAUTHENTIC`, the trust store does not contain the asset's
issuing root — re-check the bundle.

## Known issues

- **MinGW build failure.** Pinned in
  [`rust/c2pa-verify/README.md`](../rust/c2pa-verify/README.md);
  workaround is the Linux container path documented above.
  Tracked against VG-011-c in
  [`security/pre-audit-plan.md`](security/pre-audit-plan.md).
- **Post-quantum migration.** `c2pa-rs` 0.30 uses classical
  ECDSA/RSA signatures only. The migration plan to PQ-safe
  signatures is captured in
  [`../../adrs/ADR-011-post-quantum-agility.md`](../../adrs/ADR-011-post-quantum-agility.md);
  expect a c2pa-rs version bump (≥ 0.49) once upstream ships
  hybrid trust-list support.
- **OCSP stapling.** `c2pa_ocsp_enabled` is `false` by default;
  enabling it adds a network round-trip per verification and
  has not been performance-tested at scale.

## See also

- [`c2pa-integration.md`](c2pa-integration.md) — request-path,
  evidence envelope, classification semantics.
- [`c2pa-trust-store.md`](c2pa-trust-store.md) — bundle format,
  rotation cadence, mounting patterns.
- [`module-1-media-authenticity.md`](module-1-media-authenticity.md)
  — module-level overview and API surface.
- [`security/image-signing.md`](security/image-signing.md) —
  cosign verification of release images.
- [`disaster-recovery.md`](disaster-recovery.md) — trust-store
  backup and restore procedures.
- [`../../adrs/ADR-011-post-quantum-agility.md`](../../adrs/ADR-011-post-quantum-agility.md)
  — PQ migration plan for signature stacks.
