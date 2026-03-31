# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
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
