# Lab image for: phishing-detector (02-phishing-recognition)
#
# This is a minimal OCI artifact image. It contains only the compiled Wasm
# module and the lab.yaml configuration file. There is no OS layer, no shell,
# and no package manager. The sandbox-host (cyberpath-sandbox-host) loads and
# executes lab.wasm via wasmtime; Docker/containerd never actually exec into
# this container.
#
# Build inputs expected in this directory at image-build time:
#   lab.wasm   — compiled Wasm module (produced by the track build process)
#   lab.yaml   — lab configuration (already present in the source tree)
#
# The placeholder file lab.wasm.placeholder is committed in source; the track
# build process replaces it with the real lab.wasm before invoking docker build.

FROM scratch

# ── OCI standard image labels ─────────────────────────────────────────────
LABEL org.opencontainers.image.source="https://github.com/opensecstack/opensecstack" \
      org.opencontainers.image.title="phishing-detector" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="CyberPath lab: Phishing Email Classification Exercise (track 02-phishing-recognition)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="OpenSecStack"

# ── Wasm module and configuration ─────────────────────────────────────────
# lab.wasm is the compiled Wasm module; the sandbox-host mounts and runs it.
COPY lab.wasm  /lab.wasm
COPY lab.yaml  /lab.yaml

# ── Non-root user (uid 65534 = nobody) ───────────────────────────────────
# scratch has no /etc/passwd; the sandbox-host honours the numeric UID.
USER 65534

# ── Entrypoint ────────────────────────────────────────────────────────────
# The sandbox-host (wasmtime wrapper) invokes the Wasm module directly.
# This ENTRYPOINT is informational metadata consumed by the runtime; Docker
# exec is never used for lab execution.
ENTRYPOINT ["/lab.wasm"]
