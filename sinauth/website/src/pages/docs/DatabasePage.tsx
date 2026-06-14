import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const createDbCode = `-- Create the database and user
CREATE USER sinauth WITH PASSWORD 'secret';
CREATE DATABASE sinauth OWNER sinauth;
GRANT ALL PRIVILEGES ON DATABASE sinauth TO sinauth;`

const connectionCode = `# Standard connection string
DATABASE_URL=postgres://sinauth:secret@localhost:5432/sinauth

# With SSL (recommended for production)
DATABASE_URL=postgres://sinauth:secret@db.example.com:5432/sinauth?sslmode=require

# With connection pool parameters
DATABASE_URL=postgres://sinauth:secret@localhost:5432/sinauth?pool_max_conns=20&pool_min_conns=2`

const migrationsCode = `# Migrations run automatically on startup.
# To run migrations manually without starting the server:
sinauth migrate

# To check migration status:
sinauth migrate --status

# Docker equivalent:
docker run --rm \\
  -e DATABASE_URL="postgres://sinauth:secret@db:5432/sinauth" \\
  ghcr.io/opensecstack/sinauth:latest migrate`

const pgBouncerCode = `# pgBouncer config (pgbouncer.ini)
[databases]
sinauth = host=localhost port=5432 dbname=sinauth

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 20
server_reset_query = DISCARD ALL

# In sinauth, point DATABASE_URL at pgBouncer's port (default 6432)
DATABASE_URL=postgres://sinauth:secret@localhost:6432/sinauth`

const backupCode = `# Daily backup with pg_dump
pg_dump -U sinauth -Fc sinauth > sinauth_$(date +%Y%m%d).dump

# Restore
pg_restore -U sinauth -d sinauth sinauth_20260101.dump`

const toc = [
  { id: 'requirements', label: 'Requirements' },
  { id: 'create', label: 'Create the database' },
  { id: 'connection', label: 'Connection string' },
  { id: 'migrations', label: 'Migrations' },
  { id: 'pooling', label: 'Connection pooling' },
  { id: 'backup', label: 'Backup & restore' },
]

export default function DatabasePage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Configuration', 'Database Setup']}
      toc={toc}
      editPath="DatabasePage.tsx"
      prev={{ label: 'Environment Vars', path: '/docs/config' }}
      next={{ label: 'PKCE Flow', path: '/docs/pkce' }}
    >
      <h1>Database Setup</h1>

      <p>
        sinauth uses PostgreSQL as its only data store. All user accounts, OAuth2 clients,
        sessions, TOTP secrets, and the triple-hash WORM audit chain are stored in Postgres.
      </p>

      <h2 id="requirements">Requirements</h2>

      <ul>
        <li>PostgreSQL 14 or later</li>
        <li>A dedicated database and user (do not use the <code>postgres</code> superuser)</li>
        <li>The <code>pgcrypto</code> extension (enabled automatically during migration)</li>
      </ul>

      <div className="callout-note">
        <strong>Docker users:</strong> The <code>docker-compose.yml</code> from the{' '}
        <a href="/docs/quickstart" style={{ color: '#6366f1' }}>Quick Start</a> guide provisions
        Postgres automatically. You only need to follow these steps for a self-managed Postgres
        instance.
      </div>

      <h2 id="create">Create the database</h2>

      <p>
        Connect to Postgres as a superuser and create a dedicated database and user for sinauth:
      </p>

      <CodeBlock code={createDbCode} language="sql" filename="psql" />

      <h2 id="connection">Connection string</h2>

      <p>
        Set <code>DATABASE_URL</code> to a standard <code>postgres://</code> connection string.
        sinauth uses <code>pgx/v5</code> under the hood so all pgx pool parameters are supported
        as query string arguments.
      </p>

      <CodeBlock code={connectionCode} language="bash" filename=".env" />

      <div className="callout-warning">
        <strong>Production:</strong> Always use <code>sslmode=require</code> or{' '}
        <code>sslmode=verify-full</code> in production to encrypt the database connection. Never
        send credentials over an unencrypted connection.
      </div>

      <h2 id="migrations">Migrations</h2>

      <p>
        sinauth manages its schema with built-in migrations using{' '}
        <a href="https://github.com/golang-migrate/migrate" target="_blank" rel="noopener noreferrer" style={{ color: '#6366f1' }}>
          golang-migrate
        </a>
        . Migrations run automatically when the server starts. You can also run them manually or
        check their status via the CLI.
      </p>

      <CodeBlock code={migrationsCode} language="bash" filename="terminal" />

      <div className="callout-note">
        <strong>Zero-downtime upgrades:</strong> All migrations are additive. Columns are never
        dropped in the same release they are removed from code — they are marked as deprecated for
        one release cycle first. Safe to run while the previous version is still serving traffic.
      </div>

      <h2 id="pooling">Connection pooling</h2>

      <p>
        sinauth maintains its own internal connection pool via <code>pgxpool</code>. For high-load
        deployments with many sinauth replicas, place a{' '}
        <a href="https://www.pgbouncer.org/" target="_blank" rel="noopener noreferrer" style={{ color: '#6366f1' }}>
          pgBouncer
        </a>{' '}
        instance in front of Postgres and point sinauth's <code>DATABASE_URL</code> at pgBouncer.
        Use <strong>transaction mode</strong>.
      </p>

      <CodeBlock code={pgBouncerCode} language="ini" filename="pgbouncer.ini" />

      <h2 id="backup">Backup & restore</h2>

      <p>
        Use <code>pg_dump</code> for logical backups. The custom format (<code>-Fc</code>) is
        recommended — it supports parallel restore and selective table recovery.
      </p>

      <CodeBlock code={backupCode} language="bash" filename="terminal" />

      <p>
        For continuous backups in production, use WAL archiving with a tool like{' '}
        <a href="https://pgbackrest.org/" target="_blank" rel="noopener noreferrer" style={{ color: '#6366f1' }}>
          pgBackRest
        </a>{' '}
        or your cloud provider's managed Postgres snapshot feature.
      </p>
    </DocsLayout>
  )
}
