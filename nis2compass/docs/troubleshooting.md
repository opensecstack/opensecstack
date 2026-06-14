# NIS2 Compass Troubleshooting Guide

This guide covers the most common failure modes observed in NIS2 Compass. Each entry follows the same structure: Symptom, Likely Cause, Diagnosis Steps, Resolution. All commands assume Docker Compose v2 and that you are in the `nis2compass/` directory.

---

## Issue 1: API Returns 500 on All Requests

### Symptom

Every request to the API returns HTTP 500, including `GET /health`. The API container is running (`docker compose ps` shows it as `Up`) but all responses fail.

### Likely Cause

The database connection pool is exhausted, or the PostgreSQL container has become unreachable after the API started (e.g., Postgres was restarted independently).

### Diagnosis Steps

1. Inspect the API logs for connection errors:
   ```bash
   docker compose logs --tail=100 nis2compass-api
   ```
   Look for messages containing `OperationalError`, `could not connect to server`, or `too many connections`.

2. Check active connections against the pool limit:
   ```bash
   docker compose exec postgres psql -U postgres -d nis2compass -c \
     "SELECT count(*) FROM pg_stat_activity WHERE datname = 'nis2compass';"
   ```
   If the count is at or near the configured maximum connections, the pool is exhausted.

3. Confirm the Postgres container is healthy:
   ```bash
   docker compose ps postgres
   ```

### Resolution

- If the pool is exhausted, restart the API to reset all pooled connections:
  ```bash
  docker compose restart nis2compass-api
  ```
- If Postgres became unreachable, bring it back up:
  ```bash
  docker compose start postgres
  ```
  Then restart the API so it re-establishes pool connections.
- If the issue recurs, review connection pool sizing in the application configuration and investigate which clients are holding idle connections (visible in `pg_stat_activity` with `state = 'idle'`).

---

## Issue 2: Migrations Fail on Startup

### Symptom

The `migrate` service exits with a non-zero code. The `nis2compass-api` container never starts because it depends on `migrate` completing successfully. `docker compose ps` shows `migrate` as `Exited (1)`.

### Likely Cause

One of: an Alembic revision conflict (two heads in the migration chain), the database is not yet ready when the migrate service attempts to connect, or a required environment variable is not set.

### Diagnosis Steps

1. Inspect migrate service logs:
   ```bash
   docker compose logs migrate
   ```

2. Check for a `MultipleHeads` error in the output. This means two migration branches exist and Alembic cannot determine which to apply.

3. Check for a connection error. If the log shows `could not connect to server` or `Connection refused`, the Postgres service was not ready despite the `depends_on` health check (possible on slow hosts).

4. Check for a missing environment variable error such as `NIS2_DB_PASSWORD must be set`:
   ```bash
   docker compose config | grep NIS2_DB_PASSWORD
   ```

5. If migrations appear to have partially run, inspect the migration state:
   ```bash
   docker compose exec postgres psql -U postgres -d nis2compass -c \
     "SELECT * FROM alembic_version;"
   ```

### Resolution

- For a `MultipleHeads` error: merge the migration branches with `alembic merge heads` in the development environment, commit the merge migration, and redeploy.
- For a connection error: increase the `retries` and `interval` on the Postgres `healthcheck` in `docker-compose.yml`, or add an explicit `pg_isready` wait loop to the migrate service command.
- For a missing environment variable: ensure the `.env` file is present and contains all required variables. Run `docker compose --env-file .env up` explicitly, or export the variable in the shell before running Compose.

---

## Issue 3: `alembic upgrade head` Fails with "type already exists"

### Symptom

Running `alembic upgrade head` (either manually or via the migrate service) fails with an error such as:

```
sqlalchemy.exc.ProgrammingError: (psycopg2.errors.DuplicateObject) type "org_size" already exists
```

### Likely Cause

A previous migration run was interrupted after creating one or more ENUM types but before updating the `alembic_version` table. Alembic does not know the migration was partially applied, so it attempts to re-run the full migration and fails on the already-created types.

### Diagnosis Steps

1. Check which ENUM types currently exist in the database:
   ```sql
   SELECT typname FROM pg_type
   WHERE typname IN (
     'org_size', 'entity_type', 'assessment_status',
     'control_status', 'artifact_type', 'nist_category', 'audit_risk_class'
   );
   ```

2. Check the current Alembic version:
   ```bash
   docker compose exec postgres psql -U postgres -d nis2compass -c \
     "SELECT * FROM alembic_version;"
   ```
   If the table is empty or shows a revision prior to the one that creates these types, the partial run is confirmed.

### Resolution

Manually drop the orphaned types that were created by the failed migration, then re-run the migration:

```sql
DROP TYPE IF EXISTS org_size;
DROP TYPE IF EXISTS entity_type;
DROP TYPE IF EXISTS assessment_status;
-- Drop only the types that existed before any tables were created on them.
-- Do not drop types that are in use by existing columns.
```

Then re-run:

```bash
alembic upgrade head
```

If tables were partially created alongside the types, it may be safer to restore from the pre-migration backup and re-run, rather than manually cleaning up partial state.

---

## Issue 4: Seed Script Fails with "relation does not exist"

### Symptom

Running `python seeds/01_nis2_controls.py` or `python seeds/02_sample_org.py` fails with:

```
psycopg2.errors.UndefinedTable: relation "control_templates" does not exist
```

### Likely Cause

The Alembic migrations have not been applied yet. The seed scripts assume the full schema is in place.

### Diagnosis Steps

Check the Alembic version table:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT * FROM alembic_version;"
```

If this query itself fails with `relation "alembic_version" does not exist`, no migrations have been applied at all.

### Resolution

Run migrations before running seeds:

```bash
alembic upgrade head
```

Then run the seed scripts in order:

```bash
python seeds/01_nis2_controls.py
python seeds/02_sample_org.py
```

---

## Issue 5: JWT Token Rejected (401 Unauthorized)

### Symptom

API requests return HTTP 401 with a body indicating an invalid or expired token, even when a token was recently obtained.

### Likely Cause

The token has expired (tokens have a 1-hour TTL), the `NIS2_JWT_SECRET` value has changed between the token being issued and it being validated (e.g., after a container restart with a different secret), or the token is structurally malformed.

### Diagnosis Steps

1. Decode the JWT locally to check its `exp` claim:
   ```bash
   echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
   ```
   Compare the `exp` (Unix timestamp) to the current time.

2. Check whether `NIS2_JWT_SECRET` is consistent across restarts. If it is sourced from an environment variable rather than a stable secrets store, a container restart with a missing or changed `.env` entry will invalidate all existing tokens.

3. Inspect the API logs for the specific rejection reason:
   ```bash
   docker compose logs nis2compass-api | grep '"status_code":401'
   ```

### Resolution

- For an expired token: obtain a new token. Token TTL is 1 hour by design.
- For a changed `NIS2_JWT_SECRET`: ensure the secret is stable across deployments. Store it in a secrets manager or a committed `.env` file (not committed to version control, but consistently deployed). All existing tokens signed with the old secret are permanently invalidated — users must re-authenticate.
- For a malformed token: investigate the client issuing the token. The token must be a valid three-part base64url-encoded JWT.

---

## Issue 6: Rate Limiter Blocking All Requests (429 Too Many Requests)

### Symptom

All API requests return HTTP 429 regardless of the client or request rate. Legitimate traffic is being blocked.

### Likely Cause

Redis is unreachable. Depending on the application's fail-open or fail-closed configuration for rate limiting, an unreachable Redis may cause all requests to be counted against a zero-capacity limit (fail-closed) or silently allow all requests (fail-open). A Redis outage can also leave stale rate counters in place.

### Diagnosis Steps

1. Check Redis health:
   ```bash
   docker compose ps redis
   docker compose exec redis redis-cli -a "$REDIS_PASSWORD" ping
   ```

2. Check the API logs for Redis connection errors:
   ```bash
   docker compose logs nis2compass-api | grep -i redis
   ```

3. Count rate-limiter keys currently in Redis:
   ```bash
   docker compose exec redis redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'rate:*' | wc -l
   ```

### Resolution

If Redis is unreachable, bring it back up:

```bash
docker compose start redis
docker compose restart nis2compass-api
```

If Redis is reachable but stale rate counters are blocking traffic (e.g., after a misconfigured burst test):

```bash
docker compose exec redis \
  redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'rate:*' | \
  xargs docker compose exec -T redis redis-cli -a "$REDIS_PASSWORD" DEL
```

This flushes all rate-limiter state. Use only as an incident response measure.

---

## Issue 7: Artifact Upload Returns 413 Request Entity Too Large

### Symptom

Uploading a file to the artifacts endpoint returns HTTP 413.

### Likely Cause

The file exceeds the `NIS2_MAX_UPLOAD_BYTES` limit configured in the application (default: 20 MB, or 20,971,520 bytes). If the API is behind an nginx reverse proxy, nginx's own `client_max_body_size` directive may also reject the request before it reaches the application.

### Diagnosis Steps

1. Check whether the 413 is returned by nginx (check the response `Server` header) or by the application.

2. Check the current value of `NIS2_MAX_UPLOAD_BYTES` in the running container:
   ```bash
   docker compose exec nis2compass-api env | grep NIS2_MAX_UPLOAD_BYTES
   ```

3. If behind nginx, check the nginx configuration for `client_max_body_size`.

### Resolution

- If the upload is legitimately larger than the default limit and that limit should be raised, update `NIS2_MAX_UPLOAD_BYTES` in the environment configuration and restart the API.
- If nginx is the source of the 413, update `client_max_body_size` in the nginx server block to match or exceed the application limit, then reload nginx (`nginx -s reload`).
- If the file is unexpectedly large, investigate whether the client is sending the correct file.

---

## Issue 8: `audit_log is immutable` Error in Logs

### Symptom

The API logs contain an error originating from PostgreSQL:

```
EXCEPTION:  audit_log is immutable: UPDATE operations are not permitted
```

or the equivalent for DELETE.

### Likely Cause

Application code is issuing an UPDATE or DELETE statement targeting the `audit_log` table. This is a bug. The CITADEL WORM trigger raises this exception at the storage layer to enforce immutability, but the underlying cause is incorrect application logic.

### Diagnosis Steps

1. Retrieve the full stack trace from the log entry containing the exception. The stack trace will identify the code path that issued the write.

2. Confirm the trigger is in place and has not been dropped:
   ```sql
   SELECT tgname, tgenabled FROM pg_trigger
   WHERE tgrelid = 'audit_log'::regclass;
   ```
   `enforce_audit_log_immutability` should be present with `tgenabled = 'O'` (always enabled).

### Resolution

This is a code defect, not a configuration issue. Identify the code path from the stack trace and correct it so that it only ever INSERTs into `audit_log`. Under no circumstances should the trigger be disabled to work around this error. The trigger must remain in place; the application code must be fixed.

---

## Issue 9: Chain Hash Verification Fails

### Symptom

A routine or triggered chain hash verification across the `audit_log` table detects that `chain_hash` values do not match recomputed hashes, or that `prev_hash` links are broken.

### Likely Cause

This is a security incident. The audit log has been tampered with: rows have been inserted, removed, or modified outside of the normal application path. Even if the immutability trigger is in place, a database superuser can disable triggers or restore a modified snapshot.

### Diagnosis Steps

1. Identify the first row in the chain where the hash diverges. Compare computed hash against stored `chain_hash` for each row in ascending `timestamp` order.

2. Note the `id`, `timestamp`, and `chain_hash` of the last valid entry and the first invalid entry.

3. Compare the suspect region against the most recent verified backup.

### Resolution

This is a security incident. Do not attempt to repair the hash chain — doing so would further corrupt the evidence record.

1. Immediately take a snapshot of the current database state:
   ```bash
   docker compose exec postgres pg_dump -U postgres nis2compass \
     > incident_snapshot_$(date +%Y%m%d_%H%M%S).sql
   ```
2. Preserve all container logs.
3. Escalate to the security team with the snapshot, the log files, and the specific row range where the divergence was detected.
4. Do not restart or modify the database until the security team has completed their initial assessment.

---

## Issue 10: pgAdmin Cannot Connect to Postgres

### Symptom

pgAdmin reports a connection refused or authentication failed error when attempting to connect to the Postgres server.

### Likely Cause

The hostname is set to `localhost` instead of `postgres` (the Docker Compose service name). Inside the Docker network, services must refer to each other by service name, not by `localhost`. Alternatively, the port may be wrong: Postgres is on port `5432` inside the Docker network, but `5433` on the host in the development Compose configuration.

### Diagnosis Steps

1. Check the connection settings in pgAdmin:
   - **Host**: must be `postgres` (the Docker Compose service name), not `localhost` or `127.0.0.1`.
   - **Port**: `5432` when connecting from inside the Docker network. Use `5433` only when connecting from the host machine directly (dev Compose only).
   - **Username**: `postgres` (superuser) or `nis2compass` (application user).

2. Confirm pgAdmin is on the `backend` network in Docker Compose:
   ```bash
   docker compose exec pgadmin ping postgres
   ```

### Resolution

Update the pgAdmin server definition to use `postgres` as the hostname and `5432` as the port. If pgAdmin is running outside Docker and connecting to the dev environment, use `localhost:5433`.

---

## Issue 11: Alembic `Can't Locate Revision` Error

### Symptom

Running `alembic upgrade head` or `alembic current` fails with:

```
alembic.util.exc.CommandError: Can't locate revision identified by '<hash>'
```

### Likely Cause

The `alembic_version` table in the database contains a revision identifier that does not exist in the `migrations/versions/` directory. This can happen if migration files were deleted or if the database was cloned from a different branch with a different migration history.

### Diagnosis Steps

1. Check what revision the database thinks it is on:
   ```bash
   docker compose exec postgres psql -U postgres -d nis2compass -c \
     "SELECT * FROM alembic_version;"
   ```

2. List all known revisions in the migration files:
   ```bash
   alembic history
   ```

3. Identify whether the stored revision is absent from the history output.

### Resolution

If the stored revision is from a deleted or superseded branch, stamp the database to the correct current revision without running any migrations:

```bash
alembic stamp 003
```

Replace `003` with the correct revision identifier from `alembic history`. After stamping, verify:

```bash
alembic current
```

Only stamp to a revision that corresponds to the actual schema state of the database. If the schema is ahead of or behind the stamped revision, a migration run will be incorrect.

---

## Issue 12: `NIS2_DB_PASSWORD must be set` Error on docker compose up

### Symptom

Running `docker compose up` fails immediately with:

```
variable is not set. Defaulting to a blank string.
```

or:

```
NIS2_DB_PASSWORD must be set
```

### Likely Cause

The `.env` file is not present in the working directory, or the required variable is not exported in the current shell session. Docker Compose requires `NIS2_DB_PASSWORD` (and other required variables) to be available at startup.

### Diagnosis Steps

1. Check that the `.env` file exists:
   ```bash
   ls -la .env
   ```

2. Check that the file contains the required variable:
   ```bash
   grep NIS2_DB_PASSWORD .env
   ```

3. Confirm Docker Compose is reading the file:
   ```bash
   docker compose config | grep NIS2_DB_PASSWORD
   ```

### Resolution

Ensure the `.env` file exists and contains all required variables listed in the README. Then run Compose with the explicit `--env-file` flag:

```bash
docker compose --env-file .env up -d
```

Alternatively, export the variable directly in the shell:

```bash
export NIS2_DB_PASSWORD=your_password_here
docker compose up -d
```

Do not commit the `.env` file to version control. Use a secrets manager or a deployment pipeline secret injection mechanism for production environments.
