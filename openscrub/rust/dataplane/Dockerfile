# OpenScrub data-plane (Rust + Aya loader).
# Build context is rust/dataplane/.
#
# This image runs the userspace loader binary (`openscrub-loader`) only.
# It needs the host kernel's BPF subsystem; the actual eBPF object is
# embedded into the binary at build time via Aya.

FROM rust:1.81-bookworm AS build
WORKDIR /src

# Build dependencies for Aya / libbpf-sys.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        zlib1g-dev \
        pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Cache deps.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
 && cargo build --release --bin openscrub-loader \
 || true

COPY . .
RUN cargo build --release --bin openscrub-loader

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libelf1 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 9087 openscrub \
 && useradd  --system --gid 9087 --uid 9087 --home-dir /var/lib/openscrub \
             --no-create-home --shell /usr/sbin/nologin openscrub

COPY --from=build /src/target/release/openscrub-loader /usr/local/bin/openscrub-loader

# The loader runs as root by default because raising RLIMIT_MEMLOCK on
# kernels < 5.11 needs CAP_SYS_RESOURCE in the initial namespace. On
# kernel ≥ 5.11 you may add `--user 9087:9087` and rely on the explicit
# capability set provided by the orchestrator (Helm DaemonSet / compose).
USER 0:0

ENTRYPOINT ["/usr/local/bin/openscrub-loader"]
