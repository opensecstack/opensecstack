# VertGuard Dockerfile — multi-stage build producing a minimal
# runtime image. Produces ~80 MB image with Go binary + Rust libraries
# statically linked.
#
# Build: docker build -t ghcr.io/opensecstack/vertguard:dev .
# Run:   docker compose up -d (preferred) or see README.md quick-start

# ─────────────────────────────────────────────────────────────────────
# Stage 1 — Rust builder (pattern engine, C2PA)
# ─────────────────────────────────────────────────────────────────────
FROM rust:1.76-slim-bookworm AS rust-builder

WORKDIR /build

# OpenSSL build deps for c2pa-rs's `openssl_sign` feature. Adds
# ~30 MB to the build image; final-stage runtime only needs libssl3
# which is already present in distroless/base-debian12. Without these
# the c2pa-verify build fails at link-time on `-lssl -lcrypto`.
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only Cargo manifests first for dependency caching.
COPY rust/Cargo.toml rust/Cargo.lock* ./rust/
COPY rust/prompt-patterns/Cargo.toml ./rust/prompt-patterns/
COPY rust/c2pa/Cargo.toml             ./rust/c2pa/
COPY rust/c2pa-verify/Cargo.toml      ./rust/c2pa-verify/

# Placeholder src to warm cache.
RUN mkdir -p rust/prompt-patterns/src rust/c2pa/src rust/c2pa-verify/src && \
    echo "// placeholder" > rust/prompt-patterns/src/lib.rs && \
    echo "// placeholder" > rust/c2pa/src/lib.rs && \
    echo "fn main() {}" > rust/c2pa-verify/src/main.rs && \
    cd rust && cargo build --release --features ffi || true

# Copy real sources, rebuild.
COPY rust/prompt-patterns/src ./rust/prompt-patterns/src
COPY rust/c2pa/src             ./rust/c2pa/src
COPY rust/c2pa-verify/src      ./rust/c2pa-verify/src

RUN cd rust && \
    cargo build --release --features ffi && \
    cargo build --release -p c2pa-verify --bin c2pa-verify && \
    # Staticlibs + dynamiclibs go to a known output location for stage 3.
    mkdir -p /out/lib /out/bin && \
    cp target/release/*.so /out/lib/ 2>/dev/null || true && \
    cp target/release/*.a  /out/lib/ 2>/dev/null || true && \
    cp target/release/c2pa-verify /out/bin/c2pa-verify

# ─────────────────────────────────────────────────────────────────────
# Stage 2 — Go builder
# ─────────────────────────────────────────────────────────────────────
FROM golang:1.24-bookworm AS go-builder

WORKDIR /build

# Build-time args for version stamping via ldflags.
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Go-module dependency caching.
COPY go.mod go.sum* ./
RUN go mod download

# Rust artefacts from stage 1 (for CGO linking when FFI lands in v0.1+).
COPY --from=rust-builder /out/lib /usr/local/lib

# Copy Go sources.
COPY cmd/     ./cmd/
COPY internal/ ./internal/

# Build server + CLI binaries with version injection.
# CGO_ENABLED=1 once Rust FFI integration lands (VG-003); for the
# scaffold, CGO is off so the build is fully static.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w \
        -X github.com/opensecstack/vertguard/internal/version.Version=${VERSION} \
        -X github.com/opensecstack/vertguard/internal/version.GitCommit=${GIT_COMMIT} \
        -X github.com/opensecstack/vertguard/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/vertguard-server ./cmd/server

# ─────────────────────────────────────────────────────────────────────
# Stage 3 — Minimal runtime
# ─────────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/base-debian12:nonroot AS runtime

WORKDIR /app

# Copy Go binary + Rust shared libraries (when FFI is active) +
# the c2pa-verify CLI (Phase 4.2 Module 1). distroless/base-debian12
# already ships libssl3, which is the only dynamic dep c2pa-verify
# needs at runtime.
COPY --from=go-builder  /out/vertguard-server /app/vertguard-server
COPY --from=rust-builder /out/lib/            /usr/local/lib/
COPY --from=rust-builder /out/bin/c2pa-verify /usr/local/bin/c2pa-verify

# Healthcheck via wget is not available in distroless; use the Go
# binary's future `vertguard-server healthcheck` subcommand. For now,
# docker-compose does its own healthcheck via curl from outside.

# Run as the distroless nonroot user (UID 65532).
USER nonroot:nonroot

# Default port (override via env).
EXPOSE 8091

ENTRYPOINT ["/app/vertguard-server"]
