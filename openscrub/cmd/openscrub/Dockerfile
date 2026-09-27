# OpenScrub control-plane container.
#
# Multi-stage:
#   1. golang:1.25-alpine — build the static binary
#   2. gcr.io/distroless/static-debian12 — minimal runtime (no shell)
#
# Build context is the REPO ROOT, not openscrub/ — go.mod's `replace`
# directives for sdk/go/citadel and sdk/go/sinauth point outside this
# directory (../sdk/go/citadel, ../sdk/go/sinauth relative to
# openscrub/go.mod), and only resolve if sdk/ is present alongside
# openscrub/ in the build context, the same reason citadel/Dockerfile
# and threatflow/Dockerfile use root context.
#
#   docker build -f openscrub/cmd/openscrub/Dockerfile \
#     -t opensecstack/openscrub-api:dev .

FROM golang:1.25-alpine AS build
WORKDIR /src

COPY openscrub/go.mod openscrub/go.sum ./openscrub/
COPY sdk/go/citadel/go.mod sdk/go/citadel/go.sum ./sdk/go/citadel/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/openscrub
RUN go mod download

WORKDIR /src
COPY openscrub/ ./openscrub/
COPY sdk/go/citadel/ ./sdk/go/citadel/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/openscrub

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/openscrub ./cmd/openscrub

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/openscrub /usr/local/bin/openscrub

EXPOSE 8087
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/openscrub"]
