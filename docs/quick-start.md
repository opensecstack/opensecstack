# Quick Start Guide

From zero to running opensecstack in under 10 minutes.

## Prerequisites

- [Docker](https://docker.com) 24+
- [Docker Compose](https://docs.docker.com/compose/) 2.24+ (included with Docker Desktop)
- 8GB RAM minimum (16GB recommended for full stack)

## Option 1: Docker Compose (Recommended)

```bash
# Clone the ecosystem
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# Start the full stack
docker compose -f deploy/docker-compose.yml up -d

# Verify
curl http://localhost:8080/api/v1/health
# → {"status":"ok","version":"0.1.0"}

# Open the dashboard
# → http://localhost:3000
```

## Option 2: Single Platform (APIGuard)

```bash
cd opensecstack/apiguard
cp .env.example .env
make dev

# Verify
curl http://localhost:8080/api/v1/health

# Run a sample scan
make scan-example
```

## Option 3: VS Code Dev Container

1. Open the `opensecstack/` folder in VS Code
2. When prompted, click **"Reopen in Container"**
3. All tools (Go, Rust, Node.js, Python, Docker) are pre-installed
4. Run `make dev` to start the stack

## What's Running

| Service | URL | Purpose |
|---------|-----|---------|
| APIGuard API | http://localhost:8080 | API security scanner |
| Dashboard | http://localhost:3000 | Web UI |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Queue & cache |

## Next Steps

- [Run your first API scan](../apiguard/docs/quick-start.md)
- [Configure APIGuard](../apiguard/docs/configuration.md)
- [Set up CI/CD integration](../apiguard/docs/cicd-integration.md)
- [Read the architecture overview](../ECOSYSTEM.md)
