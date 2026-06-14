# Environment Setup

This document explains how to configure Docker test environments in SecureLab, including safety controls, network isolation, and teardown procedures.

## What is a SecureLab environment?

A SecureLab environment is an isolated Docker network containing one or more target services (APIs, databases, etc.) that are the subjects of attack simulations. Environments are provisioned on demand and torn down after a run completes.

All environments use Docker's `--internal` network flag, which prevents any traffic from leaving the test network. Target services can never reach production systems or the internet.

## Creating an environment

Environments are created via the API:

```bash
POST /api/v1/environments
Content-Type: application/json
Authorization: Bearer <admin-jwt>

{
  "name": "my-test-env",
  "description": "OWASP test API for Q2 validation",
  "target_url": "http://target-api:9090",
  "docker_compose_ref": "docker-compose.test.yml"
}
```

The `target_url` is validated against the safety blocklist before the environment is created. URLs matching `production`, `prod`, or other configured blocked keywords are rejected immediately.

Only users with the `admin` role can create environments.

## Safety validation

Before any environment is activated, SecureLab performs the following safety checks:

1. **Target URL blocklist check**: the URL is checked against `SECURELAB_BLOCKED_TARGETS`. Any match causes the environment to be rejected.
2. **Network isolation check**: the Docker network for the environment must have `internal: true`. Environments without this flag cannot be activated.
3. **Domain sanity check**: URLs containing `prod`, `production`, `live`, or any customer domain are blocked.

These checks run at environment creation time and again at scenario execution time.

## Network isolation

All test environments are created on an internal Docker bridge network (`securelab-test-net`). This network has `internal: true`, which means:

- Containers on this network cannot initiate connections to the internet.
- Containers cannot reach hosts outside the network (including production systems).
- Traffic is confined to the containers defined in `docker-compose.test.yml`.

The SecureLab API container connects to the test network only for the duration of a scenario run and disconnects afterward.

## Built-in target service

The repository includes a pre-built target service in `testdata/target-api/` — a minimal Go HTTP server with intentional OWASP API Top 10 vulnerabilities for testing. See `docker-compose.test.yml` for how it is provisioned.

To start the test environment:

```bash
docker compose -f docker-compose.test.yml up -d
```

## Teardown procedure

After a scenario run completes, SecureLab automatically:

1. Disconnects the API container from the test network.
2. Records the final run state in the database.
3. Emits the `securelab.run_completed` event to CITADEL.

To manually tear down a test environment:

```bash
# Via API
DELETE /api/v1/environments/{env_id}

# Via Docker Compose
docker compose -f docker-compose.test.yml down -v
```

The `down -v` flag removes the test database volume. This is recommended after each test cycle to ensure a clean state.

## Audit log

Every environment creation, activation, and deletion is recorded in the audit log. The audit log is append-only and includes the operator ID, timestamp, and action taken. It is accessible at `GET /api/v1/audit?resource_type=environment`.
