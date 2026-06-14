# syntax=docker/dockerfile:1

# ─── Stage 1: Go builder ────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Download dependencies first (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /app/server \
    ./cmd/server

# ─── Stage 2: Frontend builder ──────────────────────────────────────────────
FROM node:20-alpine AS frontend

WORKDIR /build

# Install dependencies first (cached layer)
COPY web/package*.json ./
RUN npm ci

# Build the SPA
COPY web/ ./
RUN npm run build

# ─── Stage 3: Final image ───────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget

WORKDIR /app

# Copy compiled binary
COPY --from=builder /app/server ./server

# Copy frontend build output (served by Go binary or a reverse proxy)
COPY --from=frontend /build/dist ./web/dist

# Upload directory
RUN mkdir -p /app/uploads

EXPOSE 8090

CMD ["/app/server"]
