FROM golang:1.22-alpine AS builder

RUN apk --no-cache add git

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .

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
COPY --from=builder /app/citadel .
USER citadel
EXPOSE 8099
ENTRYPOINT ["./citadel"]
