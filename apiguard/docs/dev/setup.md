# Development Setup

This guide covers everything needed to build, run, and test APIGuard locally.

---

## 1. Prerequisites

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| Go | 1.22+ | Backend services, CLI | https://go.dev/dl/ |
| Rust | 1.76+ (stable) | Parsers, analysers, CVSS scorer | https://rustup.rs/ |
| Node.js | 20+ | React dashboard | https://nodejs.org/ |
| Python | 3.12+ | HTML/PDF report generation (Jinja2) | https://www.python.org/downloads/ |
| PostgreSQL | 16+ | Persistence | https://www.postgresql.org/download/ |
| Redis | 7+ | Queue and cache | https://redis.io/download/ |
| Docker | 24+ | Containerised dev environment | https://docs.docker.com/get-docker/ |
| Docker Compose | 2.24+ | Multi-container orchestration | Included with Docker Desktop |
| golangci-lint | latest | Go linting | https://golangci-lint.run/usage/install/ |
| cargo-nextest | latest | Faster Rust test runner | https://nexte.st/book/installation.html |

---

## 2. Clone and Initial Setup

```bash
git clone https://github.com/opensecstack/apiguard.git
cd apiguard
cp .env.example .env
```

Edit `.env` to configure database credentials, Redis connection, and any API keys required for your environment.

---

## 3. Option A: Docker (Recommended)

This is the fastest way to get a fully working development environment.

```bash
make dev
```

This single command builds all containers and starts the entire stack. Once running, the following services are available:

| Service | URL | Port |
|---------|-----|------|
| API Server | http://localhost:8080 | 8080 |
| React Dashboard | http://localhost:3000 | 3000 |
| PostgreSQL | localhost:5432 | 5432 |
| Redis | localhost:6379 | 6379 |
| VAmPI (test target) | http://localhost:5000 | 5000 |

To stop everything:

```bash
make dev-down
```

To rebuild after dependency changes:

```bash
make dev-build
```

---

## 4. Option B: Manual Setup

Use this approach if you prefer running services directly on your host.

### 4.1 Install Toolchains

Install Go, Rust, Node.js, and Python at the versions listed in the prerequisites table. Verify:

```bash
go version        # go1.22+
rustc --version   # 1.76+
node --version    # v20+
python3 --version # 3.12+
```

### 4.2 Start PostgreSQL and Redis

Run only the infrastructure services via Docker:

```bash
docker compose up -d postgres redis
```

### 4.3 Run Database Migrations

```bash
make migrate
```

This applies all SQL files under `migrations/` against the configured PostgreSQL instance.

### 4.4 Build Rust Components

```bash
cd rust
cargo build
```

This compiles the parser, analyser, and CVSS scorer crates in the Rust workspace.

### 4.5 Start the Go API Server

```bash
go run ./cmd/
```

The API server listens on port 8080 by default. Override with the `API_PORT` environment variable.

### 4.6 Start the React Dashboard

```bash
cd web
npm install
npm run dev
```

The dashboard is served on port 3000 with Vite and proxies API requests to localhost:8080.

---

## 5. Running Tests

| Command | Scope |
|---------|-------|
| `make test` | Run all test suites (Go, Rust, integration) |
| `make test-go` | Go unit tests only |
| `make test-rust` | Rust tests only (uses `cargo-nextest`) |
| `make test-integration` | Integration tests (requires the full stack running) |

Examples:

```bash
# Run everything
make test

# Run only Go tests with verbose output
make test-go ARGS="-v"

# Run a specific Rust crate's tests
cd rust && cargo nextest run -p apiguard-parser
```

Integration tests (`make test-integration`) expect all services to be reachable. Start the stack with `make dev` before running them.

---

## 6. Running Linters

| Command | Scope |
|---------|-------|
| `make lint` | Run all linters |

### Go

```bash
golangci-lint run ./...
```

Configuration lives in `.golangci.yml` at the repository root.

### Rust

```bash
cd rust
cargo clippy --all-targets --all-features -- -D warnings
```

### React

```bash
cd web
npm run lint
```

Uses ESLint with the project configuration in `web/.eslintrc.*`.

---

## 7. Test Targets

APIGuard ships with pre-configured vulnerable APIs for testing.

### VAmPI

A deliberately vulnerable Flask-based REST API.

- URL: http://localhost:5000
- Source: https://github.com/erev0s/VAmPI
- Started automatically with `make dev`

### crAPI

Completely Ridiculous API -- a more complex vulnerable target with multiple services.

- URL: http://localhost:8025
- Source: https://github.com/OWASP/crAPI
- Start separately: `make target-crapi`

### Run a Sample Scan

```bash
make scan-example
```

This launches a scan against the VAmPI target on port 5000 and produces a report in the `output/` directory.

---

## 8. Project Structure

```
apiguard/
  cmd/          Go CLI and API server entry points
  internal/     Go business logic (services, handlers, models)
  rust/         Rust workspace
    parser/       OpenAPI/Swagger spec parser
    analyser/     Security rule engine and analysis
    cvss/         CVSS v3.1/v4.0 score calculator
  web/          React dashboard (Vite + TypeScript)
  docs/         Documentation
  migrations/   PostgreSQL migration files (applied in order)
  test/         Integration and end-to-end tests
  deploy/       Deployment configurations (Helm, Terraform)
```

---

## 9. Hot Reload

### Go -- air

The Docker dev environment uses [air](https://github.com/air-verse/air) for automatic Go rebuilds. Configuration is in `.air.toml`.

```bash
# If running manually, install air and run:
go install github.com/air-verse/air@latest
air
```

### React -- Vite HMR

Vite hot module replacement is enabled by default when running `npm run dev`. Changes to `.tsx` and `.ts` files reflect instantly in the browser.

### Rust -- Manual Rebuild

Rust crates must be rebuilt manually after changes:

```bash
cd rust
cargo build
```

There is no automatic hot reload for Rust components. After rebuilding, restart the Go API server to pick up the new binaries.

---

## 10. Common Issues

| Problem | Solution |
|---------|----------|
| `make dev` fails with port conflicts | Another process is using 8080, 3000, 5432, or 6379. Stop the conflicting service or change ports in `.env`. |
| Database migration errors | Ensure PostgreSQL is running and credentials in `.env` match. Run `make migrate-status` to check applied migrations. |
| `cargo build` fails with linking errors | Install system dependencies: `libssl-dev` and `pkg-config` on Debian/Ubuntu, or `openssl` via Homebrew on macOS. |
| `golangci-lint` not found | Install it: `go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest` or use the official install script. |
| `cargo-nextest` not found | Install it: `cargo install cargo-nextest --locked`. |
| Node modules out of date | Run `cd web && rm -rf node_modules && npm install`. |
| Redis connection refused | Verify Redis is running: `docker compose ps redis`. Check that `REDIS_URL` in `.env` points to the correct host and port. |
| Rust analyser produces stale results | Rebuild with `cargo build` in `rust/` and restart the API server. |
| Docker Compose version mismatch | Ensure Docker Compose v2.24+. Run `docker compose version` to verify. Upgrade Docker Desktop if needed. |
| Python report generation fails | Ensure Python 3.12+ is installed and `pip install -r requirements.txt` has been run in the project root. |
