# Build context is the repo root, not apiguard/, because go.mod's
# `replace` directive for sdk/go/sinauth points outside this directory —
# it only resolves if sdk/ is present alongside apiguard/ in the build
# context.

# Stage 1 — Rust builder
FROM rust:1.85-slim AS rust-builder
WORKDIR /build
COPY apiguard/rust/ ./rust/
RUN cd rust && cargo build --release

# Stage 2 — Go builder
FROM golang:1.25-alpine AS go-builder
WORKDIR /src
COPY apiguard/go.mod apiguard/go.sum ./apiguard/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/apiguard
RUN go mod download

WORKDIR /src
COPY apiguard/cmd/ ./apiguard/cmd/
COPY apiguard/internal/ ./apiguard/internal/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/apiguard

ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" -o /apiguard ./cmd/apiguard/

# Stage 3 — Runtime
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
RUN addgroup -S apiguard && adduser -S apiguard -G apiguard
COPY --from=go-builder  /apiguard                                   /usr/local/bin/apiguard
COPY --from=rust-builder /build/rust/target/release/apiguard-parser /usr/local/bin/apiguard-parser
USER apiguard
EXPOSE 8080
ENTRYPOINT ["apiguard"]
CMD ["server"]
