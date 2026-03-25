# ADR-002: Alembic for Database Schema Migrations

Date: 2026-03-25
Status: Accepted
Deciders: OpenSecStack core team

---

## Context

NIS2 Compass is a Python-based platform deployed across development, staging, and production environments. The database schema evolves as new compliance requirements are captured, new controls are added, and the audit infrastructure is extended. The platform needs a migration tool that:

- Versions schema changes in a traceable, linear (or mergeable) history.
- Applies changes safely and consistently across all environments from the same migration files.
- Supports rollback for failed or incorrect migrations in development and staging.
- Integrates with the Python/SQLAlchemy stack without requiring a separate runtime or binary.
- Can run as a one-shot Docker Compose service before the API starts.
- Supports offline SQL script generation for environments where direct database access from the migration tool is restricted.

---

## Decision

Use **Alembic** with **SQLAlchemy** as the database migration framework.

---

## Reasons

**Native Python, no separate binary**: Alembic is a Python package installed via `pip`. It runs in the same environment as the application, requires no JVM, no separate process manager, and no additional system packages. The `migrate` service in `docker-compose.yml` installs it with `pip install alembic psycopg2-binary sqlalchemy` and runs `alembic upgrade head` in a single command.

**SQLAlchemy integration**: Alembic is the canonical migration tool for SQLAlchemy. The `env.py` configuration file can import SQLAlchemy models directly, enabling autogenerate of migration files from model diffs during development (`alembic revision --autogenerate`). Even when autogenerate is not used, the shared SQLAlchemy dialect ensures consistent type handling between the ORM and migrations.

**Revision history chain**: Each migration file declares `revision` (its own identifier) and `down_revision` (the previous migration's identifier). Alembic validates this chain and refuses to apply migrations out of order. This prevents the class of error where a developer applies migration 003 before 002 in a freshly provisioned environment.

**Offline mode**: `alembic upgrade head --sql` generates plain SQL DDL scripts without connecting to a database. This is useful for change approval workflows where a DBA must review and approve SQL before it is applied, or for environments where the migration tool cannot connect directly to the production database.

**Environment-variable-driven connection configuration**: `env.py` reads the database connection URL from environment variables, making it straightforward to point migrations at different databases (dev, staging, prod) without modifying any files. The `docker-compose.yml` migrate service passes `NIS2_DB_*` variables into the container.

**Docker Compose one-shot service pattern**: Alembic works well as a `restart: on-failure` service that runs to completion before the API starts. Docker Compose's `depends_on` with `condition: service_completed_successfully` ensures the API only starts after migrations have been applied successfully. This eliminates the need for the API to run migrations on startup (which is error-prone in multi-replica deployments).

---

## Alternatives Considered

**Flyway**: Rejected. Flyway requires a JVM. Adding Java to the deployment stack solely for migrations introduces a significant additional dependency when the rest of the platform is pure Python. Flyway's migration files are plain SQL, which loses the Python/SQLAlchemy type integration.

**Liquibase**: Rejected. Liquibase requires a JVM and uses XML or YAML change sets. Both the JVM dependency and the XML/YAML format are unsuitable for a Python-native project. The configuration overhead is significantly higher than Alembic.

**Plain SQL scripts with manual version tracking**: Rejected. Maintaining a manual version table and applying SQL scripts in order is error-prone. There is no built-in rollback support, no chain validation to prevent out-of-order application, and no tooling to diff the current state against the target state. This approach scales poorly as the number of migrations grows.

**Django ORM migrations**: Rejected. NIS2 Compass does not use Django. Django's migration system is tightly coupled to the Django ORM model layer and cannot be used independently without importing the full Django application stack. Alembic is framework-agnostic.

---

## Consequences

- Every schema change requires an Alembic migration file in `migrations/versions/`. Direct DDL in `psql` is not permitted on any managed environment.
- Both `upgrade()` and `downgrade()` must be implemented in every migration file. The one exception is documented in ADR-003: migration 003's downgrade is effectively a no-op when `audit_log` contains rows.
- The `migrate` service adds approximately 15 seconds to cold-start time in production: `pip install` of alembic, psycopg2-binary, and sqlalchemy, followed by `alembic upgrade head`. On subsequent starts (when the image is cached and no new migrations exist), the overhead is under 5 seconds.
- Migration files must be committed to the repository. They are the authoritative record of schema history.
- For multi-replica API deployments, only one instance of the migrate service must run per deployment. Running Alembic from multiple containers simultaneously against the same database can cause race conditions on the `alembic_version` table.
