# Local Development Guide

## Prerequisites

| Tool | Version | Install | Purpose |
|------|---------|---------|---------|
| Go | 1.22+ | [go.dev/dl](https://go.dev/dl) | Backend services, CLI |
| Rust | 1.76+ (stable) | [rustup.rs](https://rustup.rs) | Parsers, analysers, crypto |
| Node.js | 20+ LTS | [nodejs.org](https://nodejs.org) | React dashboards |
| Python | 3.12+ | [python.org](https://www.python.org) | Reports, data processing |
| Docker | 24+ | [docker.com](https://docker.com) | Local stack and test targets |
| Docker Compose | 2.24+ | Included with Docker Desktop | Orchestration |
| golangci-lint | Latest | [golangci-lint.run](https://golangci-lint.run) | Go linting |
| cargo-nextest | Latest | `cargo install cargo-nextest` | Faster Rust tests |

## Running the Full Stack

```bash
# From the repo root
make dev
# This starts: APIGuard API (8080), Dashboard (3000), PostgreSQL (5432), Redis (6379)
```

Verify:
```bash
curl http://localhost:8080/api/v1/health
# → {"status":"ok"}
```

Dashboard: http://localhost:3000

## Running a Single Platform

```bash
# APIGuard only
cd apiguard
cp .env.example .env   # Edit with your values
make dev
```

## Running Without Docker

If you prefer running services directly:

```bash
# 1. Start PostgreSQL and Redis locally (or via Docker)
docker run -d --name pg -p 5432:5432 -e POSTGRES_USER=opensecstack -e POSTGRES_PASSWORD=changeme -e POSTGRES_DB=opensecstack postgres:16-alpine
docker run -d --name redis -p 6379:6379 redis:7-alpine

# 2. Run database migrations
cd apiguard && make migrate

# 3. Start Go API server
cd apiguard && go run ./cmd/

# 4. Start React dashboard (separate terminal)
cd apiguard/web && npm install && npm run dev

# 5. Build Rust components
cd apiguard/rust && cargo build --release
```

## Environment Variables

Copy `.env.example` to `.env` in the platform directory. Required variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `APIGUARD_DB_URL` | Yes | PostgreSQL connection string |
| `APIGUARD_JWT_SECRET` | Yes | JWT signing key (min 32 chars) |

See [apiguard/docs/configuration.md](../../apiguard/docs/configuration.md) for all options.

## Common Development Tasks

```bash
# Run all tests
make test

# Run linters
make lint

# Format code
make fmt

# Run a sample scan against VAmPI
cd apiguard && make scan-example

# Start test targets (VAmPI, crAPI)
cd apiguard && docker compose -f docker-compose.test.yml up -d
```

## Hot Reload

The dev Docker Compose mounts source directories as volumes. Changes to Go, Rust, and React code are picked up automatically:

- **Go**: Uses `air` for live reload
- **React**: Vite HMR
- **Rust**: Requires manual `cargo build` (compiled language)

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 5432 already in use | Stop local PostgreSQL: `sudo systemctl stop postgresql` |
| Port 8080 already in use | Change `APIGUARD_PORT` in `.env` |
| Docker out of disk space | `docker system prune -a` |
| Rust build fails | `rustup update stable` |
| Go module issues | `go mod tidy` |
