import DocsLayout from './DocsLayout'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'deployment-tiers', label: 'Deployment tiers' },
  { id: 'standard-tier', label: 'Tier 1 — Standard' },
  { id: 'elevated-tier', label: 'Tier 2 — Elevated' },
  { id: 'high-assurance-tier', label: 'Tier 3 — High assurance' },
  { id: 'cross-platform-guarantees', label: 'Cross-platform security guarantees' },
  { id: 'responsible-disclosure', label: 'Responsible disclosure' },
  { id: 'post-quantum', label: 'Post-quantum strategy' },
]

export default function SecurityPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Operations', 'Security']}
      toc={toc}
      editPath="SecurityPage.tsx"
      prev={{ label: 'Deployment', path: '/docs/deployment' }}
      next={{ label: 'Versioning & Releases', path: '/docs/releases' }}
    >
      <Helmet>
        <title>Security | opensecstack Docs</title>
        <meta
          name="description"
          content="opensecstack's three deployment security tiers, cross-platform cryptographic guarantees, responsible disclosure process, and post-quantum migration strategy."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/security" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/security" />
        <meta property="og:title" content="Security | opensecstack Docs" />
        <meta
          property="og:description"
          content="opensecstack's three deployment security tiers, cross-platform cryptographic guarantees, responsible disclosure process, and post-quantum migration strategy."
        />
      </Helmet>
      <h1>Security</h1>
      <p>
        opensecstack v1.0.0 ships with strong cryptographic primitives, structured audit, and
        role-enforced APIs. Whether those controls are <em>sufficient</em> depends on what you
        are defending against. This page defines the three deployment tiers and the
        cross-platform security guarantees that every opensecstack deployment provides. For the
        release cadence and version compatibility, see{' '}
        <a href="/docs/releases">Versioning &amp; Releases</a>.
      </p>
      <p>
        For the detailed per-tier control matrix and known gaps, see{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/docs/security-maturity.md" target="_blank" rel="noopener noreferrer">
          docs/security-maturity.md
        </a>{' '}
        and the five-layer defence model in{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/docs/security-architecture.md" target="_blank" rel="noopener noreferrer">
          docs/security-architecture.md
        </a>.
      </p>

      <h2 id="deployment-tiers">Deployment tiers</h2>
      <p>
        v1.0.0 is not a compliance certification — it is a quality mark meaning the code
        compiles, test suites pass, the API surface is frozen under semver, and the
        cryptographic primitives are state-of-the-art. Fitness for a specific deployment
        profile is tier-dependent.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Tier</th>
              <th>Your situation</th>
              <th>Is v1.0.0 sufficient?</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Standard</strong></td>
              <td>Single region, trusted operator — SaaS, NGOs, public administration, research labs</td>
              <td><strong>Yes</strong> — production-ready out of the box</td>
            </tr>
            <tr>
              <td><strong>Elevated</strong></td>
              <td>Multi-region, multi-tenant, zero-trust network expectations</td>
              <td><strong>Yes, with ops-layer additions</strong> — Vault, service mesh (mTLS), OpenTelemetry</td>
            </tr>
            <tr>
              <td><strong>High assurance</strong></td>
              <td>Banking Tier 1, national CSIRTs, <a href="/docs/nis2">NIS2</a> essential entities, defence contractors</td>
              <td><strong>Not yet</strong> — wait for v1.1 or add compensating controls</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="standard-tier">Tier 1 — Standard deployment</h2>
      <p>
        For SaaS companies, mid-sized enterprises, NGOs, regional public administration,
        and internal corporate deployments.
      </p>
      <p>Key controls shipped out of the box at this tier:</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Control</th>
              <th>Implementation</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>API authentication</td>
              <td>HS256 JWT with <code>exp</code>/<code>nbf</code> checks; <code>alg: none</code> rejected</td>
            </tr>
            <tr>
              <td>Authorization</td>
              <td>RBAC — 5 canonical roles, per-route guards (<code>RequireWrite</code>, <code>RequireDelete</code>)</td>
            </tr>
            <tr>
              <td>Webhook authentication</td>
              <td>HMAC-SHA256 with ±5-minute replay window, per-source secrets, 503 on empty secret</td>
            </tr>
            <tr>
              <td>Inter-service signing (platform → CITADEL)</td>
              <td>HMAC-SHA256 via <code>X-Citadel-Signature</code></td>
            </tr>
            <tr>
              <td>Audit integrity</td>
              <td><a href="/docs/governance">CITADEL</a> <a href="/docs/citadel/worm">WORM chain</a> — TripleHash (SHA-256 + SHA-512 + BLAKE3), Ed25519 anchors every 100 entries</td>
            </tr>
            <tr>
              <td>Dual-control enforcement</td>
              <td>CITADEL NDS — every privileged action requires operator ≠ verifier</td>
            </tr>
            <tr>
              <td>Password and API-key hashing</td>
              <td>Argon2id (RFC 9106) + HMAC-SHA256 pepper via <code>sdk/go/password</code> or <code>opensecstack-password</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="callout-note">
        <strong>Note:</strong> Before going live at Standard tier, ensure all secrets
        (<code>*_AUTH_SECRET</code>, <code>*_AUTH_PEPPER</code>, <code>CITADEL_KEY_SECRET</code>,
        and every <code>*_WEBHOOK_*_SECRET</code>) are set to at least 32 random bytes
        and are not committed to git or embedded in container images.
      </div>

      <h2 id="elevated-tier">Tier 2 — Elevated deployment</h2>
      <p>
        For multi-region SaaS, large enterprises, organisations with zero-trust mandates,
        and multi-tenant deployments.
      </p>
      <p>
        v1.0.0 is achievable at this tier with standard enterprise operations tooling — no
        code changes are required from you. The ops-layer additions you provide:
      </p>
      <ul>
        <li><strong>Secrets management</strong> — HashiCorp Vault, AWS KMS, GCP KMS, or Azure Key Vault as the source of truth; short-lived sidecars inject secrets at start-up</li>
        <li><strong>Network-level trust</strong> — service mesh (Istio, Linkerd) enforcing mTLS between every platform pair, or Cloudflare Tunnel / Tailscale for east-west traffic</li>
        <li><strong>Distributed tracing</strong> — OpenTelemetry collector forwarding <code>traceparent</code> / <code>tracestate</code> headers across platforms</li>
        <li><strong>Rate limiting</strong> — Envoy filter or API gateway with Redis-backed distributed buckets</li>
      </ul>
      <p>
        Known gaps planned for v1.1: JWKS endpoints on each platform, W3C Trace Context
        cross-platform propagation, webhook event deduplication, and mTLS-ready deployment
        templates.
      </p>

      <h2 id="high-assurance-tier">Tier 3 — High assurance</h2>
      <p>
        For banking Tier 1, national CSIRTs, critical public utilities (energy, water,
        telecom), NIS2 essential and important entities subject to competent-authority audit,
        and defence contractors.
      </p>
      <div className="callout-warning">
        <strong>Warning:</strong> Do not deploy v1.0.0 as-is to regulated critical
        infrastructure and do not advertise it as NIS2-critical-ready in procurement or
        compliance artefacts. The controls required at this tier — FIPS 140-2 Level 3 HSM
        key storage, mandatory mTLS at every boundary, signed audit trail for HARD_STOP
        events, and an independent third-party security audit — are scheduled for v1.1.
      </div>
      <p>
        If you must deploy now at this tier, compensate with operational controls: HSM-backed
        Vault, strictly segmented networks, and mandatory 2-person release reviews. Track the
        v1.1 milestone for every Tier 3 gap.
      </p>

      <h2 id="cross-platform-guarantees">Cross-platform security guarantees</h2>
      <p>
        Every opensecstack deployment — regardless of which platforms are installed —
        provides the following guarantees:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Guarantee</th>
              <th>Enforced by</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Every privileged action is cryptographically evaluated</td>
              <td>CITADEL <a href="/docs/citadel/marshal">MARSHAL</a> 5-gate engine</td>
            </tr>
            <tr>
              <td>Every decision is WORM-logged with TripleHash integrity</td>
              <td>CITADEL WORM chain (SHA-256 + SHA-512 + BLAKE3)</td>
            </tr>
            <tr>
              <td>Tamper-resistance via Ed25519 anchors</td>
              <td>CITADEL chain anchors (every 100 entries)</td>
            </tr>
            <tr>
              <td>Separation of Duties enforced at protocol level</td>
              <td>CITADEL Gate 3 (NDS) — operator ≠ verifier, different role groups</td>
            </tr>
            <tr>
              <td>All inter-platform webhooks HMAC-signed, replay-protected</td>
              <td>IRFlow webhook spec (±5-minute window, per-source secrets)</td>
            </tr>
            <tr>
              <td>Single sign-on with central MFA across all platforms</td>
              <td><a href="/docs/identity">sinauth</a> OIDC (RS256 + JWKS, PKCE S256, TOTP)</td>
            </tr>
            <tr>
              <td>All API clients JWT-authenticated with RBAC</td>
              <td>Platform auth middleware — 5 canonical roles</td>
            </tr>
            <tr>
              <td>Password hashing with Argon2id + server-side pepper</td>
              <td><code>sdk/go/password</code> + <code>sdk/python-password</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="responsible-disclosure">Responsible disclosure</h2>
      <p>
        Security vulnerabilities in any opensecstack platform should be reported privately
        before public disclosure. See{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer">
          SECURITY.md
        </a>{' '}
        for the scope, disclosure process, and SLA. Each platform also ships its own
        <code> SECURITY.md</code> covering platform-specific scope and the threat model for
        that service.
      </p>

      <h2 id="post-quantum">Post-quantum strategy</h2>
      <p>
        NIST PQC standards were finalised in 2024. NIS3 (projected 2030–2032) will likely
        mandate migration. opensecstack is moving before it is mandatory, starting from
        algorithm agility rather than a single disruptive cutover.
      </p>
      <p>
        v1.0.0 uses Ed25519 chain anchors and TripleHash as the baseline. The roadmap:
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Year</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>v1.0.0</td>
              <td>2026</td>
              <td>Ed25519 anchors + TripleHash. Baseline.</td>
            </tr>
            <tr>
              <td>v1.1</td>
              <td>2026–2027</td>
              <td>Algorithm-identifier schema fields added. No breaking change.</td>
            </tr>
            <tr>
              <td>v2.0</td>
              <td>2028</td>
              <td>Hybrid Ed25519 + ML-DSA signatures.</td>
            </tr>
            <tr>
              <td>v2.5</td>
              <td>2029</td>
              <td>QuintHash (TripleHash + 2 PQ-resistant primitives).</td>
            </tr>
            <tr>
              <td>v3.0</td>
              <td>2030</td>
              <td>ML-DSA default. Aligned with expected NIS3 transposition.</td>
            </tr>
            <tr>
              <td>v4.0</td>
              <td>2033</td>
              <td>Ed25519 signing retired; historical verification retained.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        The design principle is <strong>algorithm agility</strong> — schema fields carry
        algorithm identifiers from v1.1 so that the v2.0 hybrid switch is a configuration
        change, not a breaking API migration. Historical WORM chain entries remain verifiable
        after the algorithm transition.
      </p>
      <p>
        See{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/docs/post-quantum-roadmap.md" target="_blank" rel="noopener noreferrer">
          docs/post-quantum-roadmap.md
        </a>{' '}
        and{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/adrs/ADR-011-post-quantum-agility.md" target="_blank" rel="noopener noreferrer">
          ADR-011
        </a>{' '}
        for the full rationale.
      </p>
    </DocsLayout>
  )
}
