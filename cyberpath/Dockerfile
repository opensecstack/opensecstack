# syntax=docker/dockerfile:1.6
# Multi-stage build for the cyberpath-server binary.
# Builder uses golang:1.24-alpine; final image is distroless static.

FROM golang:1.24-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w \
      -X github.com/opensecstack/cyberpath/internal/version.Version=${VERSION} \
      -X github.com/opensecstack/cyberpath/internal/version.GitCommit=${GIT_COMMIT} \
      -X github.com/opensecstack/cyberpath/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/cyberpath-server ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/cyberpath-server /cyberpath-server
EXPOSE 8086
USER nonroot:nonroot
ENTRYPOINT ["/cyberpath-server"]
