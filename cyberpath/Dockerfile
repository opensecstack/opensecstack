# syntax=docker/dockerfile:1.6
# Multi-stage build for the cyberpath-server binary.
# Builder uses golang:1.25-alpine; final image is distroless static.
#
# Build context is the REPO ROOT, not cyberpath/ — go.mod's `replace`
# directives for sdk/go/citadel and sdk/go/sinauth point outside this
# directory, and only resolve if sdk/ is present alongside cyberpath/
# in the build context, the same reason citadel/Dockerfile and
# threatflow/Dockerfile use root context.

FROM golang:1.25-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates

COPY cyberpath/go.mod cyberpath/go.sum ./cyberpath/
COPY sdk/go/citadel/go.mod sdk/go/citadel/go.sum ./sdk/go/citadel/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/cyberpath
RUN go mod download || true

WORKDIR /src
COPY cyberpath/ ./cyberpath/
COPY sdk/go/citadel/ ./sdk/go/citadel/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/cyberpath

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
