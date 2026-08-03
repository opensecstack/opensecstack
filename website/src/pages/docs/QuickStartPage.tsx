import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'prerequisites', label: 'Prerequisites' },
  { id: 'full-stack', label: 'Full stack (Docker Compose)' },
  { id: 'service-urls', label: 'Service URLs' },
  { id: 'single-platform', label: 'Single platform (from source)' },
  { id: 'next-steps', label: 'Next steps' },
]

export default function QuickStartPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Getting Started', 'Quick Start']}
      toc={toc}
      editPath="QuickStartPage.tsx"
      prev={{ label: 'Introduction', path: '/docs/intro' }}
      next={{ label: 'Installation', path: '/docs/installation' }}
    >
      <Helmet>
        <title>Quick Start | opensecstack Docs</title>
        <meta
          name="description"
          content="Bring up the full opensecstack ecosystem with Docker Compose in under ten minutes, or run a single platform from source with make dev."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/quickstart" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/quickstart" />
        <meta property="og:title" content="Quick Start | opensecstack Docs" />
        <meta
          property="og:description"
          content="Bring up the full opensecstack ecosystem with Docker Compose in under ten minutes, or run a single platform from source with make dev."
        />
      </Helmet>
      <h1>Quick Start</h1>
      <p>
        Bring up the full opensecstack ecosystem with Docker Compose in under ten minutes, or run a
        single platform from source with <code>make dev</code>.
      </p>

      <h2 id="prerequisites">Prerequisites</h2>
      <ul>
        <li><strong>Docker 25+</strong> and <strong>Docker Compose v2.24+</strong> (included with Docker Desktop)</li>
        <li>8 GB RAM minimum — 16 GB recommended for the full stack</li>
        <li>Ports 8080, 8089, 8090, 8091, 8099, 8100, 3000, 3001, 5432, 6379 free on your machine</li>
      </ul>

      <h2 id="full-stack">Full stack (Docker Compose)</h2>
      <p>
        Clone the monorepo, copy the environment template, fill in the required secrets, then start
        all services with a single command.
      </p>
      <CodeBlock
        language="bash"
        code={`# 1. Clone the monorepo
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# 2. Copy the environment template
cp deploy/.env.example deploy/.env

# 3. Open deploy/.env and set the required secrets, for example:
#    APIGUARD_JWT_SECRET=$(openssl rand -hex 32)
#    NIS2_JWT_SECRET=$(openssl rand -hex 32)
#    POSTGRES_PASSWORD=$(openssl rand -hex 16)
#    REDIS_PASSWORD=$(openssl rand -hex 16)
#    CITADEL_API_KEY=$(openssl rand -hex 32)
#    MEILI_MASTER_KEY=$(openssl rand -hex 32)
#    COMMUNITY_JWT_SECRET=$(openssl rand -hex 32)
#    COMMUNITY_PASSWORD_PEPPER=$(openssl rand -hex 32)
#    SIN_DB_PASSWORD=$(openssl rand -hex 16)
#    SINAUTH_DB_PASSWORD=$(openssl rand -hex 16)
#    SINAUTH_ISSUER=http://localhost:8100
#    SINAUTH_SITE_URL=http://localhost:5173

# 4. Start all services in the background
docker compose -f deploy/docker-compose.yml up -d

# 5. Check every service is healthy (allow ~60 s on first boot)
docker compose -f deploy/docker-compose.yml ps`}
      />
      <div className="callout-note">
        <strong>Note:</strong> CITADEL is defined in its own compose file (
        <code>.citadel/docker-compose.yml</code>) and wired to the ecosystem via the{' '}
        <code>APIGUARD_CITADEL_URL=http://citadel-api:8099</code> env var. Start it separately or
        merge the two files for full governance integration.
      </div>

      <h2 id="service-urls">Service URLs</h2>
      <p>Once all containers are healthy the following endpoints are available:</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>URL</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr><td><a href="/docs/platforms/apiguard">APIGuard</a> API</td><td><code>http://localhost:8080</code></td><td>API security scanner</td></tr>
            <tr><td>APIGuard UI</td><td><code>http://localhost:3000</code></td><td>Scanner dashboard</td></tr>
            <tr><td><a href="/docs/platforms/nis2compass">NIS2 Compass</a> API</td><td><code>http://localhost:8090</code></td><td>NIS2 compliance engine</td></tr>
            <tr><td>NIS2 Compass UI</td><td><code>http://localhost:3001</code></td><td>Compliance dashboard</td></tr>
            <tr><td><a href="/docs/platforms/threatflow">ThreatFlow</a> API</td><td><code>http://localhost:8091</code></td><td>Threat intelligence (STIX 2.1)</td></tr>
            <tr><td><a href="/docs/platforms/community">SIN Community</a> API</td><td><code>http://localhost:8089</code></td><td>Developer knowledge hub</td></tr>
            <tr><td>CITADEL API</td><td><code>http://localhost:8099</code></td><td>Governance engine (internal)</td></tr>
            <tr><td>sinauth API</td><td><code>http://localhost:8100</code></td><td>OAuth 2.0 / OIDC identity provider</td></tr>
            <tr><td>sinauth UI</td><td><code>http://localhost:5173</code></td><td>Login portal</td></tr>
            <tr><td>PostgreSQL</td><td><code>localhost:5432</code></td><td>Shared database (internal)</td></tr>
            <tr><td>Redis</td><td><code>localhost:6379</code></td><td>Queue and cache (internal)</td></tr>
          </tbody>
        </table>
      </div>
      <p>
        Every platform also exposes <code>/health</code> on its API port. Run a quick smoke check:
      </p>
      <CodeBlock
        language="bash"
        code={`curl http://localhost:8080/health   # APIGuard
curl http://localhost:8090/health   # NIS2 Compass
curl http://localhost:8091/health   # ThreatFlow
curl http://localhost:8089/health   # SIN Community
curl http://localhost:8099/health   # CITADEL
curl http://localhost:8100/health   # sinauth`}
      />

      <h2 id="single-platform">Single platform (from source)</h2>
      <p>
        Each platform is self-contained. Use <code>make dev</code> from the platform directory to
        start it with hot reload, with its own PostgreSQL instance managed by the platform's dev
        compose file.
      </p>
      <CodeBlock
        language="bash"
        code={`# APIGuard (Go + Rust + React)
cd apiguard
cp .env.example .env
make dev
# API: http://localhost:8080  UI: http://localhost:3000

# NIS2 Compass (Python + React)
cd nis2compass
cp .env.example .env
docker compose -f docker-compose.dev.yml up -d
alembic upgrade head
cd ui && npm ci && npm run dev
# API: http://localhost:8090  UI: http://localhost:3001

# CITADEL (Go)
cd citadel
make docker-up && make migrate-up && make run
# API: http://localhost:8099

# IRFlow (Go)
cd irflow
make compose-test-up && make migrate-up && make run
# API: http://localhost:8083

# ThreatFlow (Rust + Go)
cd threatflow
docker compose up -d
# API: http://localhost:8084

# SIN Community (Go + Meilisearch)
cd community
cp .env.example .env
docker compose up -d
# API: http://localhost:8089`}
      />

      <h2 id="next-steps">Next steps</h2>
      <p>
        Now that the stack is running, explore further:
      </p>
      <ul>
        <li><a href="/docs/installation">Installation</a> — requirements, build-from-source, and Kubernetes setup</li>
        <li><a href="/docs/architecture">Architecture overview</a> — how the platforms fit together</li>
        <li><a href="/docs/deployment">Deployment</a> — Docker Compose vs Kubernetes, env/secrets, production topology</li>
        <li><a href="/docs/identity">Identity (sinauth)</a> — single sign-on and OIDC configuration</li>
        <li><a href="/docs/governance">Governance (CITADEL)</a> — MARSHAL engine and WORM audit chain</li>
      </ul>
    </DocsLayout>
  )
}
