# VertGuard ML inference Dockerfile — multi-stage build for the Python
# gRPC service. Mirrors the Go service's tag layout
# (ghcr.io/opensecstack/vertguard-ml:<version>) so a single tag push
# fans out to both images.
#
# Build: docker build -t ghcr.io/opensecstack/vertguard-ml:dev python/
# Run:   docker run --rm -p 50051:50051 ghcr.io/opensecstack/vertguard-ml:dev

# ─────────────────────────────────────────────────────────────────────
# Stage 1 — builder: protoc, deps, target install, grpc_health_probe
# ─────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.25

WORKDIR /src

# Build deps cover protoc + native wheels (grpcio sometimes needs gcc)
# and curl for grpc_health_probe download. Removed in stage 2.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        protobuf-compiler \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# grpc_health_probe is the canonical liveness/readiness probe binary for
# gRPC services on Kubernetes. Pin a release for reproducibility.
RUN curl -fsSL -o /usr/local/bin/grpc_health_probe \
        "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64" \
    && chmod +x /usr/local/bin/grpc_health_probe

# Copy proto contract before sources so generation is cacheable.
COPY proto /src/proto
COPY python/pyproject.toml /src/python/
COPY python/vertguard_ml /src/python/vertguard_ml
COPY python/scripts /src/python/scripts

# Generate proto stubs into the package's proto/ directory.
# WHY: generated stubs are not committed; the build system is the only
# thing that produces them, so the runtime image always matches the
# wire contract that was checked in at build time.
RUN python -m pip install --no-cache-dir "grpcio-tools>=1.62" "protobuf>=4.25" \
    && mkdir -p /src/python/vertguard_ml/proto \
    && python -m grpc_tools.protoc \
        -I/src/proto \
        --python_out=/src/python/vertguard_ml/proto \
        --grpc_python_out=/src/python/vertguard_ml/proto \
        /src/proto/ml/v1/inference.proto \
    && touch /src/python/vertguard_ml/proto/__init__.py

# Install runtime dependencies into a relocatable target dir.
# WHY --target: distroless-style copy in stage 2; no virtualenv needed.
# The [ml] extra is intentionally NOT installed in the default image —
# the stub backend ships everywhere; ML weights opt in via a derived
# image tag (vertguard-ml:<v>-distilbert) built from this same Dockerfile
# with --build-arg EXTRAS=ml.
ARG EXTRAS=""
RUN cd /src/python \
    && if [ -n "${EXTRAS}" ]; then \
         pip install --no-cache-dir --target /install ".[${EXTRAS}]"; \
       else \
         pip install --no-cache-dir --target /install .; \
       fi

# ─────────────────────────────────────────────────────────────────────
# Stage 2 — minimal runtime
# ─────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Match the Go image's labels so registry consumers get a uniform view.
LABEL org.opencontainers.image.vendor="opensecstack" \
      org.opencontainers.image.title="vertguard-ml" \
      org.opencontainers.image.description="VertGuard ML inference service (gRPC)" \
      org.opencontainers.image.source="https://github.com/opensecstack/vertguard" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      vendor="opensecstack" \
      component="vertguard-ml" \
      version="${VERSION}"

# Non-root user; UID matches the Go service's distroless nonroot for
# operator muscle memory.
RUN groupadd --system --gid 65532 nonroot \
    && useradd --system --uid 65532 --gid 65532 --no-create-home --shell /sbin/nologin nonroot

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/install \
    PATH=/install/bin:$PATH \
    VERTGUARD_ML_GRPC_PORT=50051 \
    VERTGUARD_ML_BACKEND=stub

COPY --from=builder /install /install
COPY --from=builder /usr/local/bin/grpc_health_probe /usr/local/bin/grpc_health_probe

USER nonroot:nonroot

EXPOSE 50051

# HEALTHCHECK uses the gRPC health protocol so docker / compose surfaces
# the same signal that Kubernetes exec-probes will.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/grpc_health_probe", "-addr=127.0.0.1:50051"]

ENTRYPOINT ["python", "-m", "vertguard_ml.server"]
