# Stage 1 — Rust builder
FROM rust:1.76-slim AS rust-builder
WORKDIR /build
COPY rust/ ./rust/
RUN cd rust && cargo build --release

# Stage 2 — Go builder
FROM golang:1.22-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" -o /apiguard ./cmd/apiguard/

# Stage 3 — Runtime
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
RUN addgroup -S apiguard && adduser -S apiguard -G apiguard
COPY --from=go-builder /apiguard /usr/local/bin/apiguard
USER apiguard
EXPOSE 8080
ENTRYPOINT ["apiguard"]
CMD ["server"]
