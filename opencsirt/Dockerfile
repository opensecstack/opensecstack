# Build context is the REPO ROOT, not opencsirt/ — go.mod's `replace`
# directives for sdk/go/sinauth and sdk/go/citadel point outside this
# directory, and only resolve if sdk/ is present alongside opencsirt/
# in the build context, the same reason citadel/Dockerfile and
# securelab/Dockerfile use root context.
#
#   docker build -f opencsirt/Dockerfile -t opensecstack/opencsirt-api:dev .

FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY opencsirt/go.mod opencsirt/go.sum ./opencsirt/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
COPY sdk/go/citadel/go.mod sdk/go/citadel/go.sum ./sdk/go/citadel/
WORKDIR /src/opencsirt
RUN go mod download

WORKDIR /src
COPY opencsirt/ ./opencsirt/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
COPY sdk/go/citadel/ ./sdk/go/citadel/
WORKDIR /src/opencsirt

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/opensecstack/opencsirt/internal/version.Version=${VERSION}" \
    -o /bin/opencsirt ./cmd/opencsirt

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S opencsirt && adduser -S opencsirt -G opencsirt

COPY --from=builder /bin/opencsirt /usr/local/bin/opencsirt
COPY --from=builder /src/opencsirt/migrations/ /etc/opencsirt/migrations/

USER opencsirt
EXPOSE 8088

ENTRYPOINT ["opencsirt"]
CMD ["serve"]
