# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024 opensecstack contributors.
#
# Multi-stage production build.
# Targets:
#   api  — distroless image running the Go HTTP server binary
#   web  — nginx image serving the built React frontend (proxies /api/ to api)
#
# Build context is the REPO ROOT, not securelab/ — go.mod's `replace`
# directive for sdk/go/sinauth (imported by
# internal/api/middleware/auth.go) points outside this directory, and
# only resolves if sdk/ is present alongside securelab/ in the build
# context, the same reason citadel/Dockerfile and
# openscrub/cmd/openscrub/Dockerfile use root context.
#
# Build with:
#   docker build --target api -f securelab/Dockerfile -t securelab-api .
#   docker build --target web -f securelab/Dockerfile -t securelab-web .

# ── Stage 1: Go builder ────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS go-builder

WORKDIR /src

# Download dependencies first (layer-cached until go.mod/go.sum change).
COPY securelab/go.mod securelab/go.sum ./securelab/
COPY sdk/go/sinauth/go.mod sdk/go/sinauth/go.sum ./sdk/go/sinauth/
WORKDIR /src/securelab
RUN go mod download

# Copy the full source and build the server binary.
WORKDIR /src
COPY securelab/ ./securelab/
COPY sdk/go/sinauth/ ./sdk/go/sinauth/
WORKDIR /src/securelab
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/securelab ./cmd/server

# ── Stage 2: Node builder (React frontend) ────────────────────────────────────
FROM node:20-alpine AS node-builder

WORKDIR /web

# Install dependencies first (layer-cached until package.json changes).
# package-lock.json is not committed, so use npm install.
COPY securelab/web/package.json ./
RUN npm install --prefer-offline

# Copy the rest of the frontend source and build.
COPY securelab/web/ .
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
COPY securelab/docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
