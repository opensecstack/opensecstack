# Quick Start

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — required to run the full stack
- [Git](https://git-scm.com/)
- [Node.js 20+](https://nodejs.org/) — only needed if you want to run the frontend outside Docker
- [Go 1.22+](https://go.dev/) — only needed if you want to run the API outside Docker

---

## 1. Clone and set up

```bash
git clone <repo>
cd community
cp .env.example .env
cp web/.env.example web/.env
```

---

## 2. Configure .env

Open `.env` and set at minimum the three required secrets:

| Variable | Description |
|---|---|
| `COMMUNITY_JWT_SECRET` | Random string, 32+ characters |
| `COMMUNITY_PASSWORD_PEPPER` | Random string used in password hashing |
| `COMMUNITY_DB_URL` | PostgreSQL connection string |

For local Docker development the default `COMMUNITY_DB_URL` in `.env.example` works as-is.
Change `COMMUNITY_JWT_SECRET` and `COMMUNITY_PASSWORD_PEPPER` to unique random values before
running — the server will refuse to start in production mode if these contain placeholder text.

---

## 3. Start with Docker

```bash
docker compose -f docker-compose.dev.yml up
```

This starts all services:

| Service | Default address |
|---|---|
| API | http://localhost:8090 |
| Frontend | http://localhost:5173 |
| PostgreSQL | localhost:5435 |
| Meilisearch | http://localhost:7700 |

Wait for the containers to finish initialising. The API prints `server listening` when ready.

---

## 4. First login

The default bootstrap user is set via `COMMUNITY_USERS` in `.env.example`:

```
Username: admin
Password: admin
```

Change these credentials immediately after your first login.

---

## 5. Running the frontend separately (faster dev iteration)

If you only need to change frontend code, you can run Vite outside Docker while keeping the
API and database inside it:

```bash
cd web && npm install && npm run dev
```

Make sure `VITE_API_URL` in `web/.env` points to the running API (`http://localhost:8090`).
Vite will serve the frontend on http://localhost:5173 and proxy API requests as configured.

---

## 6. Running the API outside Docker (optional)

```bash
go run ./cmd/server
```

You still need PostgreSQL and Meilisearch running (either via Docker or locally).
Set `COMMUNITY_DB_URL` and `MEILISEARCH_URL` in `.env` to match your setup.

---

## Common issues

**"migration error pgcrypto"**

PostgreSQL needs the `pgcrypto` extension. The migration scripts create it automatically
(`CREATE EXTENSION IF NOT EXISTS pgcrypto`). If you see this error, make sure you are
running the official `postgres` image (not a stripped variant) and that the migration
ran without being interrupted. Re-running `docker compose -f docker-compose.dev.yml up`
is usually enough.

**"index.html not found" in the browser**

This is expected in dev mode. The API does not serve the frontend — Vite does.
Open http://localhost:5173 instead of http://localhost:8090.

**Port conflicts**

If any default port is already in use on your machine, change the host-side port mapping
in `docker-compose.dev.yml`. For example, to move PostgreSQL from 5435 to 5436:

```yaml
ports:
  - "5436:5432"
```

Update `COMMUNITY_DB_URL` in `.env` to match the new host port.
