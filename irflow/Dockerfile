# Build context is the repo root (see release.yml / docker-compose), not
# irflow/, because go.mod's `replace` directives for the SDK submodules
# (sdk/go/password, sdk/go/sinauth) point outside this directory — they
# only resolve if the sdk/ tree is present alongside irflow/ in the
# build context.

# ---- Build stage ----
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY irflow/go.mod irflow/go.sum ./irflow/
COPY sdk/go/password/go.mod sdk/go/password/go.sum ./sdk/go/password/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/irflow
RUN go mod download

WORKDIR /src
COPY irflow/ ./irflow/
COPY sdk/go/password/ ./sdk/go/password/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/irflow

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/opensecstack/opensecstack/irflow/internal/version.Version=${VERSION} \
              -X github.com/opensecstack/opensecstack/irflow/internal/version.GitCommit=${GIT_COMMIT} \
              -X github.com/opensecstack/opensecstack/irflow/internal/version.BuildDate=${BUILD_DATE}" \
    -o /bin/irflow ./cmd/irflow

# ---- Runtime stage ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S irflow && adduser -S irflow -G irflow

COPY --from=builder /bin/irflow /usr/local/bin/irflow
COPY irflow/migrations/ /etc/irflow/migrations/

USER irflow
EXPOSE 8083

ENTRYPOINT ["irflow"]
CMD ["serve"]
