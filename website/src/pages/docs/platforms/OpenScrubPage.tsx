import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'key-features', label: 'Key features' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'ports-and-endpoints', label: 'Ports & endpoints' },
  { id: 'integration', label: 'Integration' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function OpenScrubPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'OpenScrub']}
      toc={toc}
      editPath="platforms/OpenScrubPage.tsx"
      prev={{ label: 'ThreatFlow', path: '/docs/platforms/threatflow' }}
      next={{ label: 'CyberPath', path: '/docs/platforms/cyberpath' }}
    >
      <Helmet>
        <title>OpenScrub — DDoS Mitigation | opensecstack Docs</title>
        <meta
          name="description"
          content="OpenScrub delivers line-rate L3/L4 DDoS packet filtering through an XDP/eBPF kernel data plane with GoBGP-driven blackhole routing."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/platforms/openscrub" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/platforms/openscrub" />
        <meta property="og:title" content="OpenScrub — DDoS Mitigation | opensecstack Docs" />
        <meta
          property="og:description"
          content="OpenScrub delivers line-rate L3/L4 DDoS packet filtering through an XDP/eBPF kernel data plane with GoBGP-driven blackhole routing."
        />
      </Helmet>
      <h1>OpenScrub</h1>
      <p>
        <strong>OpenScrub</strong> is the DDoS mitigation platform in the opensecstack (SIN)
        ecosystem. It delivers line-rate L3/L4 packet filtering through an XDP/eBPF kernel data
        plane and wraps every block decision in CITADEL-attested, WORM-anchored evidence — so
        NIS2 auditors can reconstruct what was blocked, why, and when without trusting a vendor
        log.
      </p>
      <p>
        OpenScrub ships at <strong>v1.0.0</strong> (2026-05-09) under the Apache 2.0 licence.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        Most organisations either absorb DDoS traffic in userspace (slow) or pay for an opaque
        commercial scrubbing service (expensive and unauditable). OpenScrub closes both gaps:
      </p>
      <ul>
        <li>
          <strong>Sub-microsecond drop latency.</strong> The eBPF/C program attaches at NIC
          ingress via XDP, before the kernel allocates an <code>skb</code>. A blocklist hit costs
          roughly 50 ns on commodity hardware — no userspace copy on the drop path.
        </li>
        <li>
          <strong>Audit-grade evidence.</strong> Every distinct mitigation event emits a signed{' '}
          <code>openscrub.mitigation</code> event to the CITADEL WORM ledger, satisfying NIS2
          Article 21(2)(c) incident-handling documentation requirements.
        </li>
        <li>
          <strong>Automatic IOC enforcement.</strong> A built-in ThreatFlow puller pulls
          malicious-IP IOCs on a 15-minute cadence and reconciles them directly into the BPF
          blocklist map — no copy-paste, no human-in-the-loop.
        </li>
      </ul>

      <h2 id="key-features">Key features</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Module</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>XDP loader (Rust + Aya)</td>
              <td>
                Loads the compiled eBPF object at NIC ingress, pins BPF maps under{' '}
                <code>/sys/fs/bpf/openscrub/</code>, manages program lifecycle with{' '}
                <code>CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE</code>
              </td>
            </tr>
            <tr>
              <td>eBPF/C data plane</td>
              <td>
                Per-packet <code>XDP_DROP</code> / <code>XDP_PASS</code> decisions against an LPM-trie
                blocklist map and a per-CIDR rate-limit map; SYN-cookie, UDP-flood, and ICMP-flood
                handlers in separate programs dispatched from <code>openscrub_kern.c</code>
              </td>
            </tr>
            <tr>
              <td>BGP blackhole (GoBGP)</td>
              <td>
                Embedded GoBGP speaker for Remotely Triggered Black Hole (RTBH); announces{' '}
                <code>/32</code> or <code>/128</code> host routes with RFC 7999 community{' '}
                <code>65535:666</code> to upstream transit providers; auto-withdraws after
                configurable cool-down
              </td>
            </tr>
            <tr>
              <td>Go control-plane API</td>
              <td>
                REST API on <code>:8087</code> — rules CRUD, live mitigations, JSON metrics
                snapshot, Prometheus exposition; communicates with the loader over a Unix socket
                to maintain a privilege boundary
              </td>
            </tr>
            <tr>
              <td>ThreatFlow IOC puller</td>
              <td>
                Goroutine polling the ThreatFlow malicious-IP feed every 15 minutes; diffs
                against existing <code>source='threatflow'</code> rules and inserts or withdraws
                automatically
              </td>
            </tr>
            <tr>
              <td>CITADEL evidence emitter</td>
              <td>
                Async fire-and-retry emission of <code>openscrub.mitigation</code> events,
                HMAC-SHA256 signed, to the CITADEL WORM append-only ledger
              </td>
            </tr>
            <tr>
              <td>Prometheus metrics</td>
              <td>
                <code>pps_dropped</code>, <code>pps_passed</code>, <code>rules_active</code>,{' '}
                <code>ioc_pull_latency_ms</code> — aggregated from per-CPU BPF stats maps every
                second
              </td>
            </tr>
            <tr>
              <td>React + Vite dashboard</td>
              <td>
                Operator UI on <code>:3087</code>; rules CRUD, live mitigation table, metrics
                charts; bilingual (Albanian + English)
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="architecture">Architecture</h2>
      <p>
        OpenScrub separates privilege using a Unix socket. The <strong>API process</strong> (Go,
        replicated) holds no kernel capabilities; it writes rules to PostgreSQL and sends{' '}
        <code>RULE_INSERT</code> / <code>RULE_DELETE</code> messages on{' '}
        <code>/run/openscrub/dataplane.sock</code>. The <strong>loader process</strong> (Rust +
        Aya, one per node) holds <code>CAP_BPF + CAP_NET_ADMIN</code>, owns the BPF maps, and
        never accepts network connections.
      </p>
      <p>The block-decision data flow:</p>
      <ol>
        <li>
          An operator (or the ThreatFlow puller) creates a rule via{' '}
          <code>POST /api/v1/rules</code>.
        </li>
        <li>The API validates, persists the row in PostgreSQL, and messages the loader.</li>
        <li>
          The loader writes the CIDR into the LPM-trie <code>blocklist</code> BPF map (or the{' '}
          <code>ratelimit</code> map for rate-limit rules).
        </li>
        <li>
          On every incoming packet the XDP program does an O(log W) LPM lookup — hit →{' '}
          <code>XDP_DROP</code>; miss → <code>XDP_PASS</code>.
        </li>
        <li>
          Per-CPU <code>stats</code> counters are aggregated every second; a mitigation row is
          written and a CITADEL event is emitted asynchronously.
        </li>
      </ol>
      <p>
        For volumetric attacks that exceed NIC capacity, the BGP module announces a blackhole
        route via GoBGP to upstream transit peers using the RTBH technique, shifting the drop
        point to the provider edge. The cool-down window (default 300 s) is configurable under{' '}
        <code>mitigation.bgp.withdraw_delay_seconds</code>.
      </p>

      <div className="callout-note">
        <strong>Kernel attack surface:</strong> XDP map injection, rule poisoning, and loader
        privilege escalation are treated as critical-severity findings by default. The data plane
        runs <code>privileged: false</code> with an explicit capability set and{' '}
        <code>drop: ALL</code> as the base seccomp policy. A third-party kernel-attack-surface
        audit is pending scheduling.
      </div>

      <h2 id="ports-and-endpoints">Ports &amp; endpoints</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>8087</code></td>
              <td>OpenScrub REST API (Go)</td>
            </tr>
            <tr>
              <td><code>9091</code></td>
              <td>Prometheus metrics endpoint</td>
            </tr>
            <tr>
              <td><code>3087</code></td>
              <td>React operator dashboard (nginx)</td>
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
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/health</code></td>
              <td>Liveness — status, version, DB ping, dataplane attached</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/auth/login</code></td>
              <td>JWT issuance</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/rules</code></td>
              <td>List rules (paginated; filter by type)</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/rules</code></td>
              <td>
                Create rule — type ∈ <code>blocklist</code> / <code>ratelimit</code> /{' '}
                <code>syncookie</code>
              </td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/rules/{'{id}'}</code></td>
              <td>Rule detail</td>
            </tr>
            <tr>
              <td><code>DELETE</code></td>
              <td><code>/api/v1/rules/{'{id}'}</code></td>
              <td>Withdraw rule and clear BPF map entry</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/mitigations</code></td>
              <td>Mitigation rows (filter by <code>since</code>, <code>rule_id</code>)</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/metrics/snapshot</code></td>
              <td>JSON metrics snapshot for the dashboard</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/metrics</code></td>
              <td>Prometheus text exposition (JWT-gated)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="integration">Integration</h2>
      <p>
        OpenScrub authenticates dashboard users via <a href="/docs/identity"><strong>sinauth</strong></a> SSO using the
        OAuth 2.0 <code>authorization_code + PKCE (S256)</code> flow. The API validates
        RS256-signed tokens against the sinauth JWKS endpoint at{' '}
        <code>https://auth.sin.to/.well-known/jwks.json</code>.
      </p>
      <p>Minimum required environment variables:</p>
      <CodeBlock
        language="bash"
        filename=".env"
        code={`OPENSCRUB_DB_URL=postgres://openscrub:openscrub@postgres:5432/openscrub
OPENSCRUB_DATAPLANE_SOCKET=/run/openscrub/dataplane.sock
OPENSCRUB_JWT_SECRET=<32+ random bytes>
OPENSCRUB_CITADEL_API_URL=https://citadel.internal
OPENSCRUB_CITADEL_HMAC_SECRET=<hmac secret>
OPENSCRUB_THREATFLOW_API_URL=https://threatflow.internal
OPENSCRUB_THREATFLOW_TOKEN=<bearer token>
OPENSCRUB_IFACE=eth0`}
      />
      <p>Quick start with Docker Compose:</p>
      <CodeBlock
        language="bash"
        code={`git clone https://github.com/opensecstack/opensecstack
cd opensecstack/openscrub

cp .env.example .env
docker compose -f deploy/docker-compose.yml up -d

# Health check
curl http://localhost:8087/api/v1/health

# List active rules (requires Bearer token)
curl -H "Authorization: Bearer $TOKEN" \\
     http://localhost:8087/api/v1/rules`}
      />
      <p>
        <a href="/docs/platforms/securelab">SecureLab</a> polls <code>GET /api/v1/alerts?technique={'{id}'}&amp;since={'{ts}'}</code> (read-only,
        HMAC-signed) to validate that OpenScrub detections fire as expected during attack
        simulations. <a href="/docs/platforms/threatflow">ThreatFlow</a> pushes malicious-IP IOCs inbound; <a href="/docs/governance">CITADEL</a> receives outbound
        mitigation evidence.
      </p>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete OpenScrub reference — deployment guide, XDP program guide, BGP blackhole
        setup, API reference, CITADEL integration, and threat model — is in the repository:
      </p>
      <p>
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/openscrub/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/opensecstack/opensecstack/tree/main/openscrub/docs
        </a>
      </p>
    </DocsLayout>
  )
}
