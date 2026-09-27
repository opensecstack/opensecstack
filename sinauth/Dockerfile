FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-X github.com/opensecstack/sinauth/internal/version.Version=${VERSION} \
              -X github.com/opensecstack/sinauth/internal/version.Commit=${GIT_COMMIT} \
              -X github.com/opensecstack/sinauth/internal/version.Date=${BUILD_DATE} \
              -X main.Version=${VERSION} \
              -X main.Commit=${GIT_COMMIT} \
              -X main.Date=${BUILD_DATE} \
              -w -s" \
    -o /bin/sinauth ./cmd/sinauth

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /bin/sinauth /sinauth
ENTRYPOINT ["/sinauth"]
CMD ["serve"]
