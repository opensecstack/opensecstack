import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'key-features', label: 'Key features' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'ports-endpoints', label: 'Ports & endpoints' },
  { id: 'integration', label: 'Integration' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function ThreatflowPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'ThreatFlow']}
      toc={toc}
      editPath="platforms/ThreatflowPage.tsx"
      prev={{ label: 'IRFlow', path: '/docs/platforms/irflow' }}
      next={{ label: 'OpenScrub', path: '/docs/platforms/openscrub' }}
    >
      <h1>ThreatFlow</h1>
      <p>
        <strong>ThreatFlow</strong> is the threat intelligence hub for the opensecstack ecosystem.
        It ingests indicators of compromise (IOCs) from multiple feed types, normalises them to{' '}
        <strong>STIX 2.1</strong> format, maps them to the <strong>MITRE ATT&amp;CK</strong>{' '}
        framework, and publishes enriched intelligence bundles to APIGuard, IRFlow, and NIS2
        Compass. Every ingestion, correlation, and enrichment operation is governed by CITADEL
        MARSHAL and WORM-logged.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        ThreatFlow is a Go service licensed under <strong>Apache-2.0</strong>. It listens on port{' '}
        <strong>8091</strong>, backed by PostgreSQL 16 as the IOC store and Redis 7 for hot IOC
        lookup caching (10-minute TTL, invalidated on upsert or revoke). All intelligence objects
        are stored and exchanged as STIX 2.1 bundles. Deduplication is performed by hashing the
        indicator pattern with SHA-256 before insertion.
      </p>

      <h2 id="key-features">Key features</h2>
      <ul>
        <li>
          <strong>Multi-source IOC ingestion</strong> — pulls from TAXII 2.1 servers, CSV feeds
          (abuse.ch, OTX), MISP instances (<code>/events/restSearch</code> with{' '}
          <code>to_ids=true</code>), STIX 2.1 bundles, and manual API uploads.
        </li>
        <li>
          <strong>STIX 2.1 native</strong> — all indicators are normalised to STIX 2.1 Indicator
          objects on ingest; bundles are available via <code>GET /api/v1/stix/bundles/{'{id}'}</code>.
        </li>
        <li>
          <strong>MITRE ATT&amp;CK mapping</strong> — 19 embedded techniques, 16 auto-rules, and
          feed-provided extraction for automatic TTP classification of ingested indicators.
        </li>
        <li>
          <strong>Correlation engine</strong> — 5 built-in rules (duplicate, resolves-to,
          subdomain-of, same-network, shares-cve) cross-reference new IOCs with APIGuard scan
          findings, IRFlow incidents, and existing IOCs from other feeds. High-confidence matches
          produce STIX Relationship objects and trigger webhook notifications.
        </li>
        <li>
          <strong>Feed confidence scoring</strong> — each feed source has a configurable{' '}
          <code>confidence_base</code> (0–100) propagated to all IOCs ingested from that source,
          based on historical accuracy.
        </li>
        <li>
          <strong>CITADEL MARSHAL governance</strong> — every mutation (<code>IOC_INGEST</code>,
          <code> STIX_BUNDLE_IMPORT</code>, etc.) is gated through the MARSHAL 5-gate engine
          before being persisted.
        </li>
        <li>
          <strong>CITADEL WORM logging</strong> — all ingestion and export events are emitted to
          the CITADEL WORM audit chain via a bounded async queue with graceful drain on shutdown.
        </li>
        <li>
          <strong>JWT + API key + RBAC</strong> — HS256 bearer tokens with 4 roles; API keys are
          stored as SHA-256 hashes.
        </li>
        <li>
          <strong>Redis match cache</strong> — <code>GET /match?type=X&amp;value=Y</code> lookups
          are cached in Redis with a 10-minute TTL; cache is invalidated on upsert or revoke.
        </li>
        <li>
          <strong>Rate limiting</strong> — per-IP token bucket with configurable requests-per-second
          and burst.
        </li>
      </ul>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Capability</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>IOC ingestion (manual)</td><td>v1.0</td></tr>
            <tr><td>IOC ingestion (TAXII 2.1 polling)</td><td>v1.0</td></tr>
            <tr><td>CSV feed polling (abuse.ch, OTX)</td><td>v1.0</td></tr>
            <tr><td>MISP feed polling</td><td>v1.0</td></tr>
            <tr><td>STIX 2.1 bundle ingestion and fetch</td><td>v1.0</td></tr>
            <tr><td>MITRE ATT&amp;CK mapping</td><td>v1.0</td></tr>
            <tr><td>IOC correlation engine</td><td>v1.0</td></tr>
            <tr><td>Feed confidence base scoring</td><td>v1.0</td></tr>
            <tr><td>APIGuard + IRFlow + NIS2 integration</td><td>v1.0</td></tr>
            <tr><td>CITADEL MARSHAL governance + WORM logging</td><td>v1.0</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="architecture">Architecture</h2>
      <p>
        ThreatFlow is built on Go 1.22+ with chi v5 for routing, zerolog for structured JSON
        logging, and Cobra + Viper for the CLI and configuration. The data pipeline has three
        stages:
      </p>
      <ol>
        <li>
          <strong>Ingestion</strong> — the Feed Poller pulls from configured sources; the STIX
          Parser normalises indicators; the Deduplicator checks SHA-256 of each pattern; the
          MARSHAL gate evaluates whether ingestion should proceed; PostgreSQL stores the IOC; a
          WORM event (<code>threatflow.ioc.ingested</code>) is emitted to CITADEL.
        </li>
        <li>
          <strong>Correlation</strong> — the Correlation Engine cross-references new IOCs with
          APIGuard scan findings, IRFlow open incidents, and IOCs from other feeds. Matches
          produce STIX Relationship objects; high-confidence matches trigger outbound webhooks.
        </li>
        <li>
          <strong>Export</strong> — the Export Engine assembles STIX 2.1 bundles on demand or on
          schedule, filtered by consumer (IRFlow receives incident-relevant IOCs, APIGuard receives
          URL/domain IOCs). Each export is WORM-logged with the bundle hash.
        </li>
      </ol>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Layer</th>
              <th>Technology</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Language</td><td>Go 1.22+</td></tr>
            <tr><td>HTTP framework</td><td>chi v5</td></tr>
            <tr><td>CLI</td><td>Cobra + Viper</td></tr>
            <tr><td>Database</td><td>PostgreSQL 16</td></tr>
            <tr><td>Cache</td><td>Redis 7</td></tr>
            <tr><td>Logging</td><td>zerolog (structured JSON)</td></tr>
            <tr><td>Auth</td><td>JWT (consumer API) + HMAC-SHA256 (CITADEL)</td></tr>
            <tr><td>Container</td><td>Alpine 3.19 (minimal runtime image)</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="ports-endpoints">Ports &amp; endpoints</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Default port</th>
              <th>Env var</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>ThreatFlow API</td>
              <td><code>8091</code></td>
              <td><code>THREATFLOW_PORT</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>GET</td><td><code>/api/v1/health</code></td><td>Service health check</td></tr>
            <tr><td>GET</td><td><code>/api/v1/version</code></td><td>Version information</td></tr>
            <tr><td>GET</td><td><code>/api/v1/iocs</code></td><td>List all IOCs</td></tr>
            <tr><td>POST</td><td><code>/api/v1/iocs</code></td><td>Ingest a new IOC</td></tr>
            <tr><td>GET</td><td><code>/api/v1/iocs/{'{id}'}</code></td><td>Get IOC by ID</td></tr>
            <tr><td>GET</td><td><code>/api/v1/match</code></td><td>Indicator match lookup (Redis-cached)</td></tr>
            <tr><td>GET</td><td><code>/api/v1/stix/bundles</code></td><td>List STIX 2.1 bundles</td></tr>
            <tr><td>POST</td><td><code>/api/v1/stix/bundles</code></td><td>Ingest a STIX 2.1 bundle</td></tr>
            <tr><td>GET</td><td><code>/api/v1/stix/bundles/{'{id}'}</code></td><td>Fetch a bundle (envelope + objects)</td></tr>
            <tr><td>POST</td><td><code>/api/v1/sightings</code></td><td>Receive sighting events from IRFlow / APIGuard</td></tr>
          </tbody>
        </table>
      </div>

      <CodeBlock
        language="bash"
        filename="Quick start"
        code={`# Run locally
cd threatflow
go run ./cmd/threatflow serve

# Or with Docker
docker build -t threatflow .
docker run -p 8091:8091 threatflow

# Health check
curl http://localhost:8091/api/v1/health
# {"service":"threatflow","status":"ok"}

# Ingest an IOC
curl -X POST http://localhost:8091/api/v1/iocs \\
  -H "Content-Type: application/json" \\
  -d '{"type":"ipv4-addr","value":"198.51.100.42","source":"manual"}'`}
      />

      <h2 id="integration">Integration</h2>

      <h3>sinauth (identity)</h3>
      <p>
        ThreatFlow authenticates operators via <a href="/docs/identity"><strong>sinauth</strong></a> SSO (OAuth 2.0 / OIDC,
        authorization code + PKCE). Access tokens are RS256-signed JWTs issued by{' '}
        <code>https://auth.sin.to</code> and validated against the sinauth JWKS endpoint at{' '}
        <code>https://auth.sin.to/.well-known/jwks.json</code>. See the{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sinauth/docs/integration/threatflow.md" target="_blank" rel="noopener noreferrer">
          sinauth integration guide
        </a>{' '}
        for RBAC mapping and MFA configuration.
      </p>

      <h3>CITADEL (governance)</h3>
      <p>
        ThreatFlow evaluates every mutation (<code>IOC_INGEST</code>,{' '}
        <code>STIX_BUNDLE_IMPORT</code>, and others) through <a href="/docs/governance">CITADEL</a> <a href="/docs/citadel/marshal">MARSHAL</a> before persisting
        anything. <a href="/docs/citadel/worm">WORM</a> events are emitted via a bounded async queue — the queue drains gracefully
        on shutdown. Configure with <code>THREATFLOW_CITADEL_API_URL</code>,{' '}
        <code>THREATFLOW_CITADEL_KEY_ID</code>, and <code>THREATFLOW_CITADEL_KEY_SECRET</code>.
        When <code>THREATFLOW_CITADEL_API_URL</code> is empty, CITADEL governance is disabled
        (development mode).
      </p>

      <h3>IRFlow (incident response)</h3>
      <p>
        ThreatFlow pushes STIX 2.1 IOC bundles to <a href="/docs/platforms/irflow">IRFlow</a> for enrichment of open incidents, and
        receives incident artefacts from IRFlow for retroactive IOC matching. High-confidence
        correlation matches trigger HMAC-signed outbound webhook notifications to IRFlow. IRFlow
        also forwards sighting events to <code>POST /api/v1/sightings</code> when it observes
        indicator values in incident data.
      </p>

      <h3>APIGuard (API security)</h3>
      <p>
        ThreatFlow receives scan target URLs and discovered API endpoints from <a href="/docs/platforms/apiguard">APIGuard</a> for IOC
        extraction. It returns enrichment data — known-malicious URLs and IP indicators — as STIX
        2.1 bundles for the APIGuard Unsafe Consumption of APIs (A10) and SSRF (A7) modules.
      </p>

      <h3>NIS2 Compass (compliance)</h3>
      <p>
        ThreatFlow forwards supply chain IOCs to <a href="/docs/platforms/nis2compass">NIS2 Compass</a> as STIX 2.1 artefacts for the
        Article 21(2)(d) supply chain security control. This provides verifiable, machine-readable
        evidence of threat intelligence coverage.
      </p>

      <div className="callout-note">
        <strong>Note:</strong> ThreatFlow contributes to NIS2 Article 21(2)(b) incident handling
        evidence (via IRFlow) and Article 21(2)(d) supply chain security evidence (via NIS2
        Compass). See{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/compliance.md" target="_blank" rel="noopener noreferrer">
          docs/compliance.md
        </a>{' '}
        for the full NIS2 mapping.
      </div>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete ThreatFlow documentation lives in the{' '}
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          threatflow/docs
        </a>{' '}
        folder on GitHub. Key references:
      </p>
      <ul>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/architecture.md" target="_blank" rel="noopener noreferrer">
            architecture.md
          </a>{' '}
          — system design, data flow, component interactions
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/api-reference.md" target="_blank" rel="noopener noreferrer">
            api-reference.md
          </a>{' '}
          — complete HTTP API documentation
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/stix-integration.md" target="_blank" rel="noopener noreferrer">
            stix-integration.md
          </a>{' '}
          — STIX 2.1 object types, bundle format, and TAXII polling
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/ioc-feeds.md" target="_blank" rel="noopener noreferrer">
            ioc-feeds.md
          </a>{' '}
          — feed sources, ingestion pipeline, deduplication
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/mitre-attack.md" target="_blank" rel="noopener noreferrer">
            mitre-attack.md
          </a>{' '}
          — TTP classification and tagging
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/citadel-integration.md" target="_blank" rel="noopener noreferrer">
            citadel-integration.md
          </a>{' '}
          — MARSHAL governance and WORM logging details
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/threatflow/docs/configuration.md" target="_blank" rel="noopener noreferrer">
            configuration.md
          </a>{' '}
          — environment variables and config file format
        </li>
      </ul>
    </DocsLayout>
  )
}
