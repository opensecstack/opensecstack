FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w" \
    -o /bin/opencsirt ./cmd/opencsirt

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S opencsirt && adduser -S opencsirt -G opencsirt

COPY --from=builder /bin/opencsirt /usr/local/bin/opencsirt
COPY migrations/ /etc/opencsirt/migrations/

USER opencsirt
EXPOSE 8088

ENTRYPOINT ["opencsirt"]
CMD ["serve"]
