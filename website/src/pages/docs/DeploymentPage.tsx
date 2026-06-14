import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'deployment-options', label: 'Deployment options' },
  { id: 'docker-compose', label: 'Docker Compose (Tier 1)' },
  { id: 'kubernetes-helm', label: 'Kubernetes / Helm (Tier 2)' },
  { id: 'port-matrix', label: 'Port matrix' },
  { id: 'env-secrets', label: 'Environment and secrets' },
  { id: 'citadel-wiring', label: 'CITADEL wiring' },
  { id: 'network-zones', label: 'Network zones' },
]

export default function DeploymentPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Operations', 'Deployment']}
      toc={toc}
      editPath="DeploymentPage.tsx"
      prev={{ label: 'NIS2 & EU AI Act', path: '/docs/nis2' }}
      next={{ label: 'Security', path: '/docs/security' }}
    >
      <h1>Deployment</h1>
      <p>
        opensecstack supports two primary deployment topologies: a single-host Docker Compose stack
        (Tier 1) for standard deployments, and a multi-host Kubernetes deployment with optional Helm
        chart (Tier 2) for elevated or production environments. For environment requirements and
        toolchain setup, see <a href="/docs/installation">Installation</a>.
      </p>

      <h2 id="deployment-options">Deployment options</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Option</th>
              <th>Best for</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Docker Compose</td>
              <td>Local dev, NGOs, mid-sized enterprises, research labs</td>
              <td><code>deploy/docker-compose.yml</code></td>
            </tr>
            <tr>
              <td>Kubernetes (plain YAML)</td>
              <td>Production clusters, multi-region, zero-trust environments</td>
              <td><code>deploy/k8s/</code></td>
            </tr>
            <tr>
              <td>Helm chart</td>
              <td>Parameterised production installs, GitOps workflows</td>
              <td><code>deploy/helm/opensecstack/</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="docker-compose">Docker Compose (Tier 1)</h2>
      <p>
        The <code>deploy/docker-compose.yml</code> file brings up all released platforms on a single
        Docker network with two segments: <code>frontend</code> (internet-facing services) and{' '}
        <code>backend</code> (databases, caches, internal APIs). TLS terminates at an upstream
        ingress (Traefik, nginx, or Caddy); inter-service traffic is plain HTTP inside the trusted
        Docker network.
      </p>
      <CodeBlock
        language="bash"
        code={`# Copy and populate the environment file
cp deploy/.env.example deploy/.env

# Start all services
docker compose -f deploy/docker-compose.yml up -d

# Check health of every container
docker compose -f deploy/docker-compose.yml ps

# View logs for a specific service
docker compose -f deploy/docker-compose.yml logs -f apiguard-api

# Stop without destroying data volumes
docker compose -f deploy/docker-compose.yml down

# Full teardown including volumes (destructive)
docker compose -f deploy/docker-compose.yml down -v`}
      />
      <p>
        A separate dev override file, <code>deploy/docker-compose.dev.yml</code>, is available for
        local development with mounted source directories.
      </p>

      <h2 id="kubernetes-helm">Kubernetes / Helm (Tier 2)</h2>
      <p>
        For multi-host or zero-trust environments, the Kubernetes manifests in{' '}
        <code>deploy/k8s/</code> deploy each platform as a <code>Deployment</code> with readiness
        and liveness probes, ClusterIP services, and nginx Ingress resources.
      </p>
      <CodeBlock
        language="bash"
        code={`# Apply namespace first
kubectl apply -f deploy/k8s/namespace.yaml

# Create secrets (never commit real values)
kubectl create secret generic opensecstack-db-secrets \\
  --namespace opensecstack \\
  --from-literal=POSTGRES_PASSWORD='<strong-password>'

kubectl create secret generic opensecstack-app-secrets \\
  --namespace opensecstack \\
  --from-literal=APIGUARD_JWT_SECRET='<random-min-32-chars>' \\
  --from-literal=NIS2_JWT_SECRET='<random-min-32-chars>' \\
  --from-literal=REDIS_PASSWORD='<strong-password>'

# Apply all manifests recursively
kubectl apply -f deploy/k8s/ -R -n opensecstack

# Watch pods come up
kubectl get pods -n opensecstack -w`}
      />

      <h3>Helm</h3>
      <CodeBlock
        language="bash"
        code={`cp deploy/helm/opensecstack/values.prod.yaml.example \\
   deploy/helm/opensecstack/values.prod.yaml
# Edit values.prod.yaml — set image tags, replica counts, ingress hosts

helm install opensecstack deploy/helm/opensecstack/ \\
  --namespace opensecstack --create-namespace \\
  --values deploy/helm/opensecstack/values.prod.yaml

# Rolling upgrade
helm upgrade opensecstack deploy/helm/opensecstack/ \\
  --namespace opensecstack \\
  --values deploy/helm/opensecstack/values.prod.yaml`}
      />
      <div className="callout-note">
        <strong>Note:</strong> Ingress hostnames default to{' '}
        <code>apiguard.opensecstack.local</code> and{' '}
        <code>nis2compass.opensecstack.local</code>. Update the <code>host:</code> field in each
        ingress manifest before applying to production.
      </div>

      <h2 id="port-matrix">Port matrix</h2>
      <p>All API services expose <code>/health</code> and <code>/metrics</code> on their main port.</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>API port</th>
              <th>Dashboard</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            <tr><td><a href="/docs/platforms/apiguard">APIGuard</a></td><td>8080</td><td>3000</td><td>Public-facing scanning engine</td></tr>
            <tr><td><a href="/docs/platforms/nis2compass">NIS2 Compass</a></td><td>8090</td><td>3001</td><td>Python + Flask</td></tr>
            <tr><td><a href="/docs/platforms/threatflow">ThreatFlow</a></td><td>8091</td><td>—</td><td>Threat intelligence (STIX 2.1)</td></tr>
            <tr><td><a href="/docs/platforms/irflow">IRFlow</a></td><td>8083</td><td>—</td><td>Incident response orchestrator</td></tr>
            <tr><td><a href="/docs/platforms/community">SIN Community</a></td><td>8089</td><td>—</td><td>Developer knowledge hub; Meilisearch on :7700 (internal)</td></tr>
            <tr><td><a href="/docs/governance">CITADEL</a></td><td>8099</td><td>—</td><td>Internal-only; governance engine</td></tr>
            <tr><td>sinauth</td><td>8100</td><td>5173</td><td>OAuth 2.0 / OIDC identity provider</td></tr>
            <tr><td><a href="/docs/platforms/vertguard">VertGuard</a></td><td>8091</td><td>3009</td><td>AI-attack defence; ML gRPC side-car on :50051 (internal)</td></tr>
            <tr><td><a href="/docs/platforms/opencsirt">OpenCSIRT</a></td><td>8088</td><td>3088</td><td>Python advisory sub-system on :8089 (internal)</td></tr>
            <tr><td><a href="/docs/platforms/openscrub">OpenScrub</a></td><td>8087</td><td>3087</td><td>XDP/eBPF DDoS mitigation; hostNetwork on edge nodes</td></tr>
            <tr><td>PostgreSQL</td><td>5432</td><td>—</td><td>One DB instance per platform for isolation</td></tr>
            <tr><td>Redis</td><td>6379</td><td>—</td><td>Queue and cache (internal)</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="env-secrets">Environment and secrets</h2>
      <p>
        All runtime configuration is driven by environment variables. The canonical template is{' '}
        <code>deploy/.env.example</code>. Copy it to <code>deploy/.env</code> before starting the
        stack and fill in every required value.
      </p>
      <p>Key variables to set for a minimal deployment:</p>
      <CodeBlock
        language="bash"
        filename="deploy/.env (excerpt)"
        code={`# Database
POSTGRES_PASSWORD=<strong-password>
NIS2_DB_PASSWORD=<strong-password>
SIN_DB_PASSWORD=<strong-password>
SINAUTH_DB_PASSWORD=<strong-password>

# Redis
REDIS_PASSWORD=<strong-password>

# JWT signing secrets (generate with: openssl rand -hex 32)
APIGUARD_JWT_SECRET=<random-min-32-chars>
NIS2_JWT_SECRET=<random-min-32-chars>
NIS2_SECRET_KEY=<random-min-32-chars>
COMMUNITY_JWT_SECRET=<random-min-32-chars>
COMMUNITY_PASSWORD_PEPPER=<random-min-32-chars>

# CITADEL HMAC secrets
CITADEL_API_KEY=<random-min-32-chars>
IRFLOW_CITADEL_KEY_SECRET=<random-min-32-chars>
IRFLOW_WEBHOOK_APIGUARD_SECRET=<random-min-32-chars>
IRFLOW_WEBHOOK_CITADEL_SECRET=<random-min-32-chars>
IRFLOW_WEBHOOK_THREATFLOW_SECRET=<random-min-32-chars>

# Meilisearch
MEILI_MASTER_KEY=<random-min-32-chars>

# sinauth (OIDC issuer URLs)
SINAUTH_ISSUER=https://auth.example.com
SINAUTH_SITE_URL=https://auth.example.com`}
      />
      <div className="callout-warning">
        <strong>Warning:</strong> Never commit <code>deploy/.env</code> to source control. For
        production, replace env var injection with a secret manager (HashiCorp Vault, AWS Secrets
        Manager, or GCP Secret Manager) and rotate HMAC secrets quarterly and the CITADEL anchor
        key yearly. See <a href="/docs/security">Security</a> for the full deployment-tier
        control matrix.
      </div>

      <h2 id="citadel-wiring">CITADEL wiring</h2>
      <p>
        CITADEL is the governance layer and is intentionally deployed separately — its compose file
        lives under <code>.citadel/docker-compose.yml</code>. Every platform that emits governance
        events must be pointed at the CITADEL API:
      </p>
      <CodeBlock
        language="yaml"
        filename="docker-compose.yml (apiguard-api excerpt)"
        code={`environment:
  - APIGUARD_CITADEL_URL=http://citadel-api:8099
  - APIGUARD_CITADEL_API_KEY=\${CITADEL_API_KEY:-}`}
      />
      <p>
        When running the full stack with both compose files on the same Docker network, use the
        service hostname <code>citadel-api</code> and port <code>8099</code> as the base URL. All
        platform-to-CITADEL calls are HMAC-SHA256 signed with the shared <code>CITADEL_API_KEY</code>{' '}
        secret and include a ±5-minute replay window.
      </p>
      <p>
        If CITADEL is unreachable, all MARSHAL-gated actions across the ecosystem are blocked and
        platforms return HTTP 503 to callers — they never silently proceed.
      </p>

      <h2 id="network-zones">Network zones</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Zone</th>
              <th>Contains</th>
              <th>Access</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Public</strong></td>
              <td>Ingress / WAF, dashboards (APIGuard UI, NIS2 Compass UI)</td>
              <td>Internet-facing</td>
            </tr>
            <tr>
              <td><strong>Application</strong></td>
              <td>Platform API servers (ports 8080–8100)</td>
              <td>Ingress + internal services only</td>
            </tr>
            <tr>
              <td><strong>Governance</strong></td>
              <td>CITADEL (:8099)</td>
              <td>Only IRFlow, APIGuard, NIS2 Compass, ThreatFlow</td>
            </tr>
            <tr>
              <td><strong>Data</strong></td>
              <td>PostgreSQL (:5432), Redis (:6379)</td>
              <td>Owning platform only</td>
            </tr>
            <tr>
              <td><strong>Observability</strong></td>
              <td>Prometheus, Grafana, Jaeger</td>
              <td>Internal ops network only</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        For Tier 2 multi-host deployments, a service mesh (Istio or Linkerd) enforces mTLS between
        every pair of platforms, and CITADEL runs in active/passive HA with an external leader lock
        (Consul Lease or Kubernetes Lease) to keep the WORM chain single-writer.
      </p>
    </DocsLayout>
  )
}
