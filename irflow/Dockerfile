# ---- Build stage ----
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)" \
    -o /bin/irflow ./cmd/irflow

# ---- Runtime stage ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S irflow && adduser -S irflow -G irflow

COPY --from=builder /bin/irflow /usr/local/bin/irflow
COPY migrations/ /etc/irflow/migrations/

USER irflow
EXPOSE 8083

ENTRYPOINT ["irflow"]
CMD ["serve"]
