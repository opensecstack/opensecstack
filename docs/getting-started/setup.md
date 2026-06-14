# Developer Setup — Full opensecstack Ecosystem

This guide walks you through setting up the complete opensecstack
monorepo for local development. If you only need one platform, jump
to the per-platform quick-start section and skip the rest.

---

## Prerequisites

Install the following tools before cloning the repo. Versions listed
are the minimum tested; newer patch releases are generally safe.

### Required for all platforms

| Tool | Minimum version | Purpose |
|---|---|---|
| Git | 2.40+ | Source control |
| Docker | 25.0+ | Per-platform dev stacks, integration tests |
| Docker Compose | v2.24+ | Full-stack local orchestration |
| PostgreSQL client (`psql`) | 16 | Database inspection and migrations |

### Go (APIGuard, CITADEL, IRFlow, ThreatFlow, OpenCSIRT)

Install Go 1.24 or later. The recommended method is the official
binary from https://go.dev/dl/:

```bash
# Linux / macOS
wget https://go.dev/dl/go1.24.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

Verify:

```bash
go version
# go version go1.24.x linux/amd64
```

### Rust (APIGuard L1/L5, ThreatFlow, sandbox-host, SDK Rust crate)

Install the stable toolchain via rustup (https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install stable
rustup target add wasm32-wasip2   # required for CyberPath lab builds
```

Verify:

```bash
rustc --version
# rustc 1.76.x (...)
cargo --version
# cargo 1.76.x (...)
```

### Python (NIS2 Compass, IRFlow report module, SDK Python crate)

Python 3.12 is required. Use pyenv or your OS package manager:

```bash
# pyenv (recommended for reproducibility)
pyenv install 3.12.3
pyenv global 3.12.3

# Verify
python --version
# Python 3.12.3
```

### Node.js and npm (APIGuard dashboard, NIS2 Compass dashboard)

Node.js 20 LTS:

```bash
# nvm (recommended)
nvm install 20
nvm use 20

# Verify
node --version
# v20.x.x
npm --version
# 10.x.x
```

### Optional: cargo-component (CyberPath lab authoring only)

Required only if you are building CyberPath Wasm lab modules:

```bash
cargo install cargo-component
```

---

## Cloning the monorepo

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack
```

The monorepo layout:

```
opensecstack/
├── apiguard/       Go + Rust + Python + React
├── nis2compass/    Python + React
├── citadel/        Go
├── irflow/         Go + Python
├── threatflow/     Rust + Go
├── cyberpath/      Go + React + Rust (scaffold)
├── vertguard/      Go + Rust + Python (scaffold)
├── sdk/            Go · Python · TypeScript · Rust
├── deploy/         Docker Compose + Kubernetes manifests
├── docs/           Ecosystem-level documentation
└── adrs/           Architecture Decision Records
```

---

## Per-platform development setup

Run these commands from the repo root. Each platform is self-contained;
you can set up only the platforms you need.

### APIGuard

```bash
cd apiguard

# Go dependencies
go mod download

# Rust components (OpenAPI parser, static analyser)
cargo build --release -p apiguard-parser -p apiguard-analyser

# Python report module
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# React dashboard
cd ui && npm ci && cd ..

# Start with hot reload
make dev
```

APIGuard API: http://localhost:8080
APIGuard UI: http://localhost:3000

### NIS2 Compass

```bash
cd nis2compass

# Python environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start dev stack (PostgreSQL included)
docker compose -f docker-compose.dev.yml up -d

# Apply migrations
alembic upgrade head

# React dashboard
cd ui && npm ci && npm run dev
```

NIS2 Compass API: http://localhost:8090
NIS2 Compass UI: http://localhost:3001

### CITADEL

```bash
cd citadel

# Go dependencies
go mod download

# Start dev stack (PostgreSQL included)
make docker-up

# Apply migrations
make migrate-up

# Run CITADEL
make run
```

CITADEL API: http://localhost:8099

### IRFlow

```bash
cd irflow

# Go dependencies
go mod download

# Start test stack (PostgreSQL + seed data)
make compose-test-up

# Apply migrations
make migrate-up

# Run IRFlow
make run
```

IRFlow API: http://localhost:8083

### ThreatFlow

```bash
cd threatflow

# Rust + Go build
cargo build --release
go mod download

# Start with Docker Compose (PostgreSQL included)
docker compose up -d
```

ThreatFlow API: http://localhost:8084

### VertGuard (scaffold — Phase 4.1)

```bash
cd vertguard

# Go skeleton
go mod download

# Start scaffold stack
docker compose up -d
```

VertGuard API: http://localhost:8091
Phase 4.1 endpoints return HTTP 501. See
[vertguard/README.md](../../vertguard/README.md) for which endpoints
are implemented.

---

## Running the full stack locally

The `deploy/` directory contains a Docker Compose file that brings
up all production platforms together. This is the closest local
approximation of the Tier 1 deployment described in
[docs/deployment-topology.md](../deployment-topology.md).

### 1. Copy and fill in the environment file

```bash
cp deploy/.env.example deploy/.env
```

Open `deploy/.env` and set the required secrets. At minimum:

```
# JWT signing keys (generate with: openssl rand -hex 32)
APIGUARD_JWT_SECRET=<your-secret>
NIS2_JWT_SECRET=<your-secret>
IRFLOW_AUTH_SECRET=<your-secret>

# CITADEL
CITADEL_ANCHOR_KEY=<your-ed25519-private-key-hex>
IRFLOW_CITADEL_KEY_SECRET=<your-secret>

# HMAC webhook secrets (generate with: openssl rand -hex 32)
IRFLOW_WEBHOOK_APIGUARD_SECRET=<your-secret>
IRFLOW_WEBHOOK_CITADEL_SECRET=<your-secret>
IRFLOW_WEBHOOK_THREATFLOW_SECRET=<your-secret>

# IRFlow API key pepper
IRFLOW_AUTH_PEPPER=<your-secret>
```

Secrets marked `<your-secret>` can be random hex strings for local
development. Do not reuse local secrets in staging or production.

### 2. Start the stack

```bash
docker compose -f deploy/docker-compose.yml up -d
```

### 3. Verify all services are healthy

```bash
docker compose -f deploy/docker-compose.yml ps
```

All services should show `healthy` within 60 seconds. If a service
stays `starting`, check its logs:

```bash
docker compose -f deploy/docker-compose.yml logs <service-name>
```

### 4. Run smoke tests

```bash
# APIGuard health
curl http://localhost:8080/health

# CITADEL health
curl http://localhost:8099/health

# IRFlow health
curl http://localhost:8083/health

# NIS2 Compass health
curl http://localhost:8090/health

# ThreatFlow health
curl http://localhost:8084/health
```

All should return HTTP 200 with a JSON body.

---

## Running tests per platform

Each platform has its own test suite. Run them from the platform
directory.

### APIGuard

```bash
cd apiguard
go test ./...                   # Go unit + integration tests
cargo test                      # Rust unit tests
pytest tests/                   # Python report tests
```

### NIS2 Compass

```bash
cd nis2compass
pytest tests/ -v
```

### CITADEL

```bash
cd citadel
go test ./...
make test-integration           # requires Docker (spins up PostgreSQL)
```

### IRFlow

```bash
cd irflow
go test ./...
make compose-test-up && go test ./... -tags=integration
```

### ThreatFlow

```bash
cd threatflow
cargo test
go test ./...
```

### SDK

```bash
cd sdk/go && go test ./...
cd sdk/python && pytest tests/
cd sdk/rust && cargo test
```

---

## Common first-run issues and fixes

### PostgreSQL connection refused

The Go services connect to PostgreSQL on `localhost:5432` when running
outside Docker. If you are running a platform binary directly (not
via Docker Compose), start a local PostgreSQL instance or expose the
Compose PostgreSQL port:

```bash
docker run -d \
  -e POSTGRES_PASSWORD=dev \
  -e POSTGRES_USER=dev \
  -e POSTGRES_DB=dev \
  -p 5432:5432 \
  postgres:16-alpine
```

Set the `DATABASE_URL` environment variable to match:

```
DATABASE_URL=postgres://dev:dev@localhost:5432/dev?sslmode=disable
```

### Port already in use

If another process is bound to a platform port (e.g. 8080), stop it
before starting the Compose stack:

```bash
# Find the process
lsof -i :8080          # macOS / Linux
netstat -ano | findstr 8080   # Windows

# Kill it, then restart the stack
docker compose -f deploy/docker-compose.yml restart apiguard
```

### Migration failures (relation does not exist)

If a service starts before its PostgreSQL instance is ready, the
migration runner may fail. Re-run migrations manually:

```bash
# CITADEL
cd citadel && make migrate-up

# IRFlow
cd irflow && make migrate-up

# NIS2 Compass
cd nis2compass && alembic upgrade head
```

### Rust build fails (missing toolchain)

Ensure the stable toolchain is active:

```bash
rustup show          # should list stable as active
rustup update stable
```

If you see linker errors on Linux, install `build-essential` (Debian)
or `base-devel` (Arch) or the equivalent for your distribution.

### Docker Compose v1 vs v2

The repo uses `docker compose` (v2, plugin). If your system has
only `docker-compose` (v1), upgrade:

```bash
sudo apt-get install docker-compose-plugin    # Debian / Ubuntu
brew install docker-compose                   # macOS Homebrew
```

### CITADEL HMAC signature mismatch

If CITADEL rejects webhooks with `invalid signature`, verify that the
shared secret in `deploy/.env` matches on both sides. For local
development the simplest fix is:

```bash
docker compose -f deploy/docker-compose.yml down
# Edit deploy/.env — ensure IRFLOW_CITADEL_KEY_SECRET is set consistently
docker compose -f deploy/docker-compose.yml up -d
```

---

## Per-platform quick-start links

| Platform | Quick-start reference |
|---|---|
| APIGuard | [apiguard/README.md](../../apiguard/README.md) |
| NIS2 Compass | [nis2compass/README.md](../../nis2compass/README.md) |
| CITADEL | [citadel/README.md](../../citadel/README.md) |
| IRFlow | [irflow/README.md](../../irflow/README.md) |
| ThreatFlow | [threatflow/README.md](../../threatflow/README.md) |
| VertGuard (scaffold) | [vertguard/README.md](../../vertguard/README.md) |
| Go SDK | [sdk/go/README.md](../../sdk/go/README.md) |
| Python SDK | [sdk/python/README.md](../../sdk/python/README.md) |
| TypeScript SDK | [sdk/typescript/README.md](../../sdk/typescript/README.md) |
| Rust SDK | [sdk/rust/README.md](../../sdk/rust/README.md) |

---

## Related

- [CONTRIBUTING.md](../../CONTRIBUTING.md) — contribution workflow, branch policy, PR checklist
- [docs/deployment-topology.md](../deployment-topology.md) — port matrix, network segments, Tier 1 vs Tier 2 topology
- [docs/security-maturity.md](../security-maturity.md) — deployment tier guidance
- [deploy/k8s/README.md](../../deploy/k8s/README.md) — Kubernetes manifests for production deployment
