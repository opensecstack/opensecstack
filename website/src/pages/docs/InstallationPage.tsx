import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'requirements', label: 'Requirements' },
  { id: 'docker-compose', label: 'Docker Compose' },
  { id: 'kubernetes', label: 'Kubernetes' },
  { id: 'from-source', label: 'From source' },
  { id: 'next-steps', label: 'Next steps' },
]

export default function InstallationPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Getting Started', 'Installation']}
      toc={toc}
      editPath="InstallationPage.tsx"
      prev={{ label: 'Quick Start', path: '/docs/quickstart' }}
      next={{ label: 'Local Development', path: '/docs/local-dev' }}
    >
      <h1>Installation</h1>
      <p>
        opensecstack can be installed in three ways: via Docker Compose (recommended for{' '}
        <a href="/docs/local-dev">local development</a> and small deployments), via Kubernetes
        manifests or Helm (production), or built from source per platform.
      </p>

      <h2 id="requirements">Requirements</h2>
      <p>
        The minimum toolchain depends on your chosen install path. Docker Compose only requires
        Docker. Building from source requires the full toolchain.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Minimum version</th>
              <th>Used by</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Docker</td><td>25.0+</td><td>All install paths</td></tr>
            <tr><td>Docker Compose</td><td>v2.24+ (plugin)</td><td>Docker Compose install path</td></tr>
            <tr><td>Go</td><td>1.24+</td><td>APIGuard, CITADEL, IRFlow, ThreatFlow, OpenCSIRT, sinauth, SIN Community</td></tr>
            <tr><td>Rust</td><td>1.76+</td><td>APIGuard (parser/analyser), ThreatFlow, SDK Rust crate</td></tr>
            <tr><td>Python</td><td>3.12+</td><td>NIS2 Compass, IRFlow report module, SDK Python crate</td></tr>
            <tr><td>Node.js</td><td>20 LTS (18 minimum)</td><td>APIGuard UI, NIS2 Compass UI, sinauth UI, website</td></tr>
            <tr><td>PostgreSQL client</td><td>16+</td><td>Database inspection and migrations</td></tr>
            <tr><td>kubectl</td><td>1.28+</td><td>Kubernetes install path</td></tr>
            <tr><td>Helm</td><td>3.14+</td><td>Helm install path</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="docker-compose">Docker Compose</h2>
      <p>
        The recommended path for local development and Tier 1 single-host deployments. The compose
        file at <code>deploy/docker-compose.yml</code> brings up all currently-released platforms
        along with shared PostgreSQL 16 and Redis 7.
      </p>
      <CodeBlock
        language="bash"
        code={`# Clone the monorepo
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# Copy the environment template and fill in secrets
cp deploy/.env.example deploy/.env
# Edit deploy/.env — at minimum set POSTGRES_PASSWORD, REDIS_PASSWORD,
# APIGUARD_JWT_SECRET, NIS2_JWT_SECRET, MEILI_MASTER_KEY,
# COMMUNITY_JWT_SECRET, COMMUNITY_PASSWORD_PEPPER,
# SIN_DB_PASSWORD, SINAUTH_DB_PASSWORD, SINAUTH_ISSUER, SINAUTH_SITE_URL

# Start all services
docker compose -f deploy/docker-compose.yml up -d

# Tail logs for a specific service
docker compose -f deploy/docker-compose.yml logs -f apiguard-api

# Stop and remove containers (data volumes are preserved)
docker compose -f deploy/docker-compose.yml down`}
      />
      <div className="callout-note">
        <strong>Note:</strong> Use <code>docker compose</code> (Compose v2 plugin), not the legacy{' '}
        <code>docker-compose</code> v1 binary. Upgrade with{' '}
        <code>sudo apt-get install docker-compose-plugin</code> on Debian/Ubuntu or via Docker
        Desktop on macOS/Windows.
      </div>

      <h2 id="kubernetes">Kubernetes</h2>
      <p>
        Plain Kubernetes YAML manifests live in <code>deploy/k8s/</code>. A Helm chart is available
        at <code>deploy/helm/opensecstack/</code> for parameterised production installs.
      </p>

      <h3>Plain manifests</h3>
      <CodeBlock
        language="bash"
        code={`# Prerequisites: kubectl configured, nginx Ingress controller installed

# 1. Create the namespace
kubectl apply -f deploy/k8s/namespace.yaml

# 2. Create secrets (never commit real secret values)
kubectl create secret generic opensecstack-db-secrets \\
  --namespace opensecstack \\
  --from-literal=POSTGRES_PASSWORD='<strong-password>' \\
  --from-literal=NIS2_DB_PASSWORD='<strong-password>'

kubectl create secret generic opensecstack-app-secrets \\
  --namespace opensecstack \\
  --from-literal=APIGUARD_JWT_SECRET='<random-min-32-chars>' \\
  --from-literal=NIS2_JWT_SECRET='<random-min-32-chars>' \\
  --from-literal=REDIS_PASSWORD='<strong-password>'

# 3. Apply all manifests recursively
kubectl apply -f deploy/k8s/ -R -n opensecstack

# 4. Watch rollout progress
kubectl rollout status deployment/apiguard -n opensecstack
kubectl rollout status deployment/nis2compass -n opensecstack

# 5. Port-forward for local access (if no Ingress)
kubectl port-forward svc/apiguard-service 8080:8080 -n opensecstack
kubectl port-forward svc/nis2compass-service 8090:8090 -n opensecstack`}
      />
      <p>
        The manifest directory structure mirrors the topology: <code>postgres/</code>,{' '}
        <code>redis/</code>, <code>apiguard/</code>, <code>nis2compass/</code>, with Ingress
        resources defaulting to <code>apiguard.opensecstack.local</code> and{' '}
        <code>nis2compass.opensecstack.local</code> — update the <code>host:</code> field before
        applying to production.
      </p>

      <h3>Helm chart</h3>
      <CodeBlock
        language="bash"
        code={`# Copy the values template for your environment
cp deploy/helm/opensecstack/values.prod.yaml.example deploy/helm/opensecstack/values.prod.yaml

# Edit values.prod.yaml — set image tags, replica counts, ingress hosts, secret refs

# Lint and dry-run
helm lint deploy/helm/opensecstack/ -f deploy/helm/opensecstack/values.prod.yaml
helm install opensecstack deploy/helm/opensecstack/ \\
  --namespace opensecstack --create-namespace \\
  --values deploy/helm/opensecstack/values.prod.yaml \\
  --dry-run

# Install
helm install opensecstack deploy/helm/opensecstack/ \\
  --namespace opensecstack --create-namespace \\
  --values deploy/helm/opensecstack/values.prod.yaml

# Upgrade (rolling)
helm upgrade opensecstack deploy/helm/opensecstack/ \\
  --namespace opensecstack \\
  --values deploy/helm/opensecstack/values.prod.yaml`}
      />

      <h2 id="from-source">From source</h2>
      <p>
        Each platform ships a <code>Makefile</code>. The <code>make dev</code> target starts the
        platform with hot reload. Run these commands from the monorepo root.
      </p>
      <CodeBlock
        language="bash"
        code={`# Go platforms (APIGuard, CITADEL, IRFlow, sinauth, SIN Community)
go version   # must be 1.24+

cd apiguard && go mod download && make dev   # :8080
cd citadel  && go mod download && make dev   # :8099
cd irflow   && go mod download && make dev   # :8083
cd sinauth  && go mod download && make dev   # :8100
cd community && go mod download && make dev  # :8089

# Rust components (APIGuard parser/analyser, ThreatFlow)
rustup toolchain install stable
rustup target add wasm32-wasip2   # CyberPath lab builds only
cargo build --release -p apiguard-parser -p apiguard-analyser

# Python platform (NIS2 Compass)
python --version   # must be 3.12+
cd nis2compass
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose -f docker-compose.dev.yml up -d
alembic upgrade head
# API on :8090, UI: cd ui && npm ci && npm run dev (:3001)

# Node dashboards
node --version   # must be 18+ (20 LTS recommended)
cd apiguard/ui && npm ci && npm run dev    # :3000
cd sinauth/web && npm ci && npm run dev    # :5173`}
      />
      <div className="callout-warning">
        <strong>Warning:</strong> The Rust stable toolchain must be active (<code>rustup show</code>
        ) before building APIGuard or ThreatFlow. On Linux, ensure <code>build-essential</code>{' '}
        (Debian/Ubuntu) or <code>base-devel</code> (Arch) is installed to avoid linker errors.
      </div>

      <h2 id="next-steps">Next steps</h2>
      <ul>
        <li><a href="/docs/quickstart">Quick Start</a> — bring up the full stack in under ten minutes with Docker Compose</li>
        <li><a href="/docs/architecture">Architecture overview</a> — understand how the platforms fit together</li>
        <li><a href="/docs/deployment">Deployment</a> — production topology, env/secrets, and Kubernetes networking</li>
        <li><a href="/docs/identity">Identity (sinauth)</a> — configure single sign-on for the ecosystem</li>
      </ul>
    </DocsLayout>
  )
}
