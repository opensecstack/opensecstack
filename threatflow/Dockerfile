# Build context is the repo root, not threatflow/, because go.mod's
# `replace` directive for sdk/go/sinauth points outside this directory —
# it only resolves if sdk/ is present alongside threatflow/ in the build
# context.

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY threatflow/go.mod threatflow/go.sum ./threatflow/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/threatflow
RUN go mod download

WORKDIR /src
COPY threatflow/ ./threatflow/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/threatflow
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w \
      -X github.com/opensecstack/threatflow/internal/version.Version=$(cat VERSION 2>/dev/null || echo dev) \
      -X github.com/opensecstack/threatflow/internal/version.GitCommit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
      -X github.com/opensecstack/threatflow/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /bin/threatflow ./cmd/threatflow

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -g '' threatflow

COPY --from=builder /bin/threatflow /usr/local/bin/threatflow

USER threatflow
WORKDIR /app

EXPOSE 8091

ENTRYPOINT ["threatflow"]
CMD ["serve"]
