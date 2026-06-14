# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024 opensecstack contributors.
#
# Multi-stage production build.
# Targets:
#   api  — distroless image running the Go HTTP server binary
#   web  — nginx image serving the built React frontend (proxies /api/ to api)
#
# Build with:
#   docker build --target api -t securelab-api .
#   docker build --target web -t securelab-web .

# ── Stage 1: Go builder ────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS go-builder

WORKDIR /src

# Download dependencies first (layer-cached until go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source and build the server binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/securelab ./cmd/server

# ── Stage 2: Node builder (React frontend) ────────────────────────────────────
FROM node:20-alpine AS node-builder

WORKDIR /web

# Install dependencies first (layer-cached until package.json changes).
# package-lock.json is not committed, so use npm install.
COPY web/package.json ./
RUN npm install --prefer-offline

# Copy the rest of the frontend source and build.
COPY web/ .
RUN npm run build

# ── Stage 3: api — minimal distroless runtime for the Go binary ───────────────
FROM gcr.io/distroless/static-debian12:nonroot AS api

COPY --from=go-builder /out/securelab /securelab

EXPOSE 8080

USER nonroot

ENTRYPOINT ["/securelab"]

# ── Stage 4: web — nginx serving the built React frontend ────────────────────
FROM nginx:1.27-alpine AS web

COPY --from=node-builder /web/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
