# syntax=docker/dockerfile:1

# Build context is the repo root, not community/, because go.mod's
# `replace` directive for sdk/go/citadel points outside this directory —
# it only resolves if sdk/ is present alongside community/ in the build
# context.

# ─── Stage 1: Go builder ────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Download dependencies first (cached layer)
COPY community/go.mod community/go.sum ./community/
COPY sdk/go/citadel/go.mod sdk/go/citadel/go.sum ./sdk/go/citadel/
WORKDIR /src/community
RUN go mod download

# Copy source and build
WORKDIR /src
COPY community/ ./community/
COPY sdk/go/citadel/ ./sdk/go/citadel/
WORKDIR /src/community

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /app/server \
    ./cmd/server

# ─── Stage 2: Frontend builder ──────────────────────────────────────────────
FROM node:20-alpine AS frontend

WORKDIR /build

# Install dependencies first (cached layer)
COPY community/web/package*.json ./
RUN npm ci

# Build the SPA
COPY community/web/ ./
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
