# OpenScrub control-plane container.
#
# Multi-stage:
#   1. golang:1.22-alpine — build the static binary
#   2. gcr.io/distroless/static-debian12 — minimal runtime (no shell)
#
# Build context is the openscrub/ module root:
#   docker build -f cmd/openscrub/Dockerfile -t opensecstack/openscrub:dev .

FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/openscrub ./cmd/openscrub

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/openscrub /usr/local/bin/openscrub

EXPOSE 8087
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/openscrub"]
