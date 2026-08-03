# Build context is the repo root, not citadel/, because go.mod's
# `replace` directive for sdk/go/sinauth points outside this directory —
# it only resolves if sdk/ is present alongside citadel/ in the build
# context.

FROM golang:1.25-alpine AS builder

RUN apk --no-cache add git

WORKDIR /src
COPY citadel/go.mod citadel/go.sum ./citadel/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/citadel
RUN go mod download

WORKDIR /src
COPY citadel/ ./citadel/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/citadel

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-X github.com/opensecstack/citadel/internal/version.Version=${VERSION} \
              -X github.com/opensecstack/citadel/internal/version.GitCommit=${GIT_COMMIT} \
              -X github.com/opensecstack/citadel/internal/version.BuildDate=${BUILD_DATE}" \
    -o citadel ./cmd/citadel

FROM alpine:3.20
RUN apk --no-cache add ca-certificates wget
RUN addgroup -S citadel && adduser -S citadel -G citadel
WORKDIR /app
COPY --from=builder /src/citadel/citadel .
USER citadel
EXPOSE 8099
ENTRYPOINT ["./citadel"]
