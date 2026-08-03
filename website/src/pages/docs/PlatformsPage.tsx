import DocsLayout from './DocsLayout'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'all-platforms', label: 'All platforms' },
  { id: 'api-security-compliance', label: 'API security & compliance' },
  { id: 'incident-intelligence', label: 'Incident response & threat intelligence' },
  { id: 'network-training-simulation', label: 'Network defence, training & simulation' },
  { id: 'csirt-ai-community', label: 'CSIRT, AI defence & community' },
  { id: 'cross-cutting', label: 'Cross-cutting layers' },
]

export default function PlatformsPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'Platforms Overview']}
      toc={toc}
      editPath="PlatformsPage.tsx"
      prev={{ label: 'SDK & Contracts', path: '/docs/contracts' }}
      next={{ label: 'APIGuard', path: '/docs/platforms/apiguard' }}
    >
      <Helmet>
        <title>Platforms Overview | opensecstack Docs</title>
        <meta
          name="description"
          content="A complete reference table of all 11 opensecstack security platforms — purpose, tech stack, and licence — plus the sinauth identity and CITADEL governance layers."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/platforms" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/platforms" />
        <meta property="og:title" content="Platforms Overview | opensecstack Docs" />
        <meta
          property="og:description"
          content="A complete reference table of all 11 opensecstack security platforms — purpose, tech stack, and licence — plus the sinauth identity and CITADEL governance layers."
        />
      </Helmet>
      <h1>Platforms Overview</h1>
      <p>
        opensecstack ships <strong>11 security platforms</strong> plus two cross-cutting
        layers (<a href="/docs/identity">sinauth</a> for identity and{' '}
        <a href="/docs/governance">CITADEL</a> for governance). All platforms are at
        v1.0.0 production. Tool platforms are licensed under Apache 2.0 so they can be
        embedded in CI/CD pipelines; governance platforms are AGPL-3.0 so modifications
        to the audit trail and compliance reporting remain open source.
      </p>

      <h2 id="all-platforms">All platforms</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>Purpose</th>
              <th>Stack</th>
              <th>Licence</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong><a href="/docs/platforms/apiguard">APIGuard</a></strong></td>
              <td>API security testing — OWASP API Top 10 (A1–A10), CVSS 3.1, SARIF/HTML/PDF/JSON reports</td>
              <td>Go + Rust + Python + React</td>
              <td>Apache 2.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/nis2compass">NIS2 Compass</a></strong></td>
              <td>NIS2 Article 21(2) compliance assessment, evidence management, Article 23 notification</td>
              <td>Python + Go + React</td>
              <td>AGPL-3.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/irflow">IRFlow</a></strong></td>
              <td>Incident response orchestration — playbooks, governed actions, NIS2 72-hour notification</td>
              <td>Go + Python</td>
              <td>AGPL-3.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/threatflow">ThreatFlow</a></strong></td>
              <td>Threat intelligence aggregation — IOC ingestion, STIX 2.1, MITRE ATT&amp;CK</td>
              <td>Rust + Go</td>
              <td>Apache 2.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/openscrub">OpenScrub</a></strong></td>
              <td>DDoS mitigation at kernel level — XDP/eBPF programs, GoBGP blackhole routing</td>
              <td>Rust + C + Go</td>
              <td>Apache 2.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/cyberpath">CyberPath</a></strong></td>
              <td>Security training — Docker/Wasm labs, NIS2 Art. 21(2)(g) evidence records</td>
              <td>Go + React + Python</td>
              <td>Apache 2.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/securelab">SecureLab</a></strong></td>
              <td>Attack simulation &amp; detection validation — MITRE ATT&amp;CK scenario library</td>
              <td>Python + Rust + Go</td>
              <td>Apache 2.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/opencsirt">OpenCSIRT</a></strong></td>
              <td>National/sector CSIRT operations — TAXII 2.1, STIX 2.1, CSAF 2.0 advisory generation</td>
              <td>Go + Python</td>
              <td>AGPL-3.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/vertguard">VertGuard</a></strong></td>
              <td>AI-attack defence — deepfake detection, prompt injection (OWASP LLM Top 10), MITRE ATLAS threat feed, C2PA media authenticity</td>
              <td>Go + Rust + Python</td>
              <td>AGPL-3.0</td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/community">SIN Community</a></strong></td>
              <td>Developer knowledge hub — posts, tags, full-text search (Meilisearch), notifications, TOTP, API keys, spaces</td>
              <td>Go + React + TypeScript + PostgreSQL</td>
              <td>Apache 2.0</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>Note:</strong> SIN Community is the 11th platform and lives at{' '}
        <strong>sin.to</strong>. sinauth and CITADEL are not listed in the table above
        because they are cross-cutting layers, not security tool platforms — see the{' '}
        <a href="#cross-cutting">section below</a>.
      </div>

      <h2 id="api-security-compliance">API security &amp; compliance</h2>
      <p>
        <strong>APIGuard</strong> is the entry point for most security workflows. It parses
        OpenAPI 3.x and Swagger 2.0 specs through a Rust-powered parser, runs a
        10-layer testing pipeline (HTTP engine, authentication analysis, input validation,
        OWASP module runner, and more), and produces findings with CVSS 3.1 scores and
        full remediation guidance. Reports are available in JSON, SARIF, HTML, and PDF for
        CI/CD integration.
      </p>
      <p>
        <strong>NIS2 Compass</strong> manages the 10 security measures required by NIS2
        Article 21(2). It maintains an evidence vault where APIGuard scan results, CyberPath
        training records, and manual artifacts are linked to specific controls. When a
        critical incident triggers Article 23 notification requirements, it coordinates
        with IRFlow to track the 72-hour reporting deadline. Every compliance state change
        is anchored in the CITADEL WORM chain for auditor access.
      </p>

      <h2 id="incident-intelligence">Incident response &amp; threat intelligence</h2>
      <p>
        <strong>IRFlow</strong> orchestrates incident response through a graph-based
        playbook executor with branching logic and per-step timeouts. It ingests
        HMAC-signed webhooks from APIGuard, CITADEL, and ThreatFlow. Every governed action
        inside a playbook (deploy a mitigation, update a control) is evaluated by CITADEL
        MARSHAL before execution. IRFlow implements the five canonical RBAC roles used
        across the ecosystem: admin, operator, verifier, viewer, and service.
      </p>
      <p>
        <strong>ThreatFlow</strong> aggregates threat intelligence from MISP, AlienVault
        OTX, VirusTotal, and custom feeds. It normalises IOCs to STIX 2.1 bundles, maps
        techniques to MITRE ATT&amp;CK, and distributes enriched feeds downstream:
        OpenScrub receives auto-block rules, IRFlow receives incident enrichment, and
        OpenCSIRT receives advisory inputs.
      </p>

      <h2 id="network-training-simulation">Network defence, training &amp; simulation</h2>
      <p>
        <strong>OpenScrub</strong> operates at the kernel level, using XDP/eBPF programs
        written in C and Rust/Aya for packet-level filtering and GoBGP for blackhole route
        announcements. It receives auto-block rules from ThreatFlow IOC bundles and
        validated DDoS rule sets from SecureLab simulations.
      </p>
      <p>
        <strong>CyberPath</strong> delivers security training through Docker and
        WebAssembly labs. Content is authored as YAML + Markdown. Completion records are
        SDK-typed <code>TrainingRecord</code> events that feed NIS2 Compass as Art. 21(2)(g)
        evidence and are anchored in CITADEL for the audit trail.
      </p>
      <p>
        <strong>SecureLab</strong> runs attack simulations mapped to the MITRE ATT&amp;CK
        framework and validates detection rules across the ecosystem: OpenScrub DDoS rules,
        APIGuard detection patterns, ThreatFlow correlation rules, and VertGuard
        AI-attack patterns. Simulation results are typed <code>SimulationResult</code>{' '}
        events consumed by IRFlow, OpenScrub, ThreatFlow, and VertGuard.
      </p>

      <h2 id="csirt-ai-community">CSIRT, AI defence &amp; community</h2>
      <p>
        <strong>OpenCSIRT</strong> provides national and sector CSIRT operations: a
        TAXII 2.1 server and client, STIX 2.1 object model, CSAF 2.0 advisory generation,
        and NIS2 Article 23 aggregate reporting. Advisories flow into ThreatFlow as an
        IOC pipeline and cross-border AI attack incidents are coordinated with VertGuard.
      </p>
      <p>
        <strong>VertGuard</strong> defends against AI-specific attacks across five modules:
        media authenticity (C2PA + deepfake detection), AI phishing detection, prompt
        injection defence (OWASP LLM Top 10), AI threat intelligence feed (MITRE ATLAS),
        and synthetic identity detection. High-confidence AI-attack detections auto-create
        incidents in IRFlow and feed CITADEL as evidence via the Content Provenance
        (C2PA) contract.
      </p>
      <p>
        <strong>SIN Community</strong> is the developer knowledge hub at{' '}
        <strong>sin.to</strong>. It provides posts, comments, tags, full-text search
        powered by Meilisearch, spaces, notification feeds, TOTP two-factor authentication,
        and API key management for integrations. It is the 11th opensecstack platform and
        the community's primary collaboration space.
      </p>

      <h2 id="cross-cutting">Cross-cutting layers</h2>
      <p>
        Two components span every platform in the ecosystem:
      </p>
      <ul>
        <li>
          <strong>sinauth</strong> (Go + PostgreSQL, Apache 2.0) — the identity layer.
          A dedicated OAuth 2.0 / OpenID Connect authorization server that provides
          single sign-on for all platforms. RS256-signed tokens, JWKS endpoint, PKCE,
          TOTP MFA, Google and GitHub social login. As of v1.1, it also recognizes
          organizations (government, private, e-commerce, NGO) as identity subjects
          alongside individual users, with optional org-scoped token claims and an
          org picker for users belonging to more than one organization. What Auth0 is
          globally, sinauth is for the SIN ecosystem. See{' '}
          <a href="/docs/identity">Identity (sinauth)</a>.
        </li>
        <li>
          <strong>CITADEL</strong> (Go, AGPL-3.0) — the governance layer. Every
          privileged action across all platforms is evaluated by the MARSHAL 5-gate
          engine and recorded in an append-only WORM audit chain with TripleHash
          integrity (SHA-256 + SHA-512 + BLAKE3) and Ed25519 chain anchors. NDS enforces
          separation of duties at the protocol level. See{' '}
          <a href="/docs/governance">Governance (CITADEL)</a>.
        </li>
      </ul>
    </DocsLayout>
  )
}
