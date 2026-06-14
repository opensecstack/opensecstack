import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'versioning', label: 'Semantic versioning' },
  { id: 'release-types', label: 'Release types & cadence' },
  { id: 'compatibility-matrix', label: 'Compatibility matrix' },
  { id: 'support-windows', label: 'Support windows' },
  { id: 'deprecation-policy', label: 'Deprecation policy' },
  { id: 'post-quantum-timeline', label: 'Post-quantum migration timeline' },
]

export default function ReleasesPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Operations', 'Versioning & Releases']}
      toc={toc}
      editPath="ReleasesPage.tsx"
      prev={{ label: 'Security', path: '/docs/security' }}
    >
      <h1>Versioning &amp; Releases</h1>
      <p>
        The opensecstack ecosystem uses <strong>per-platform semantic versioning</strong> for
        independent release cadences and <strong>ecosystem release tags</strong> that pin a
        tested combination of platform versions for operators who want a single blessed
        configuration. This page covers the versioning rules, the compatibility matrix concept,
        the deprecation policy, and the post-quantum migration timeline. For how the platforms
        fit together structurally, see the <a href="/docs/architecture">Architecture overview</a>.
      </p>

      <h2 id="versioning">Semantic versioning</h2>
      <p>
        Every platform follows <a href="https://semver.org" target="_blank" rel="noopener noreferrer">semver.org</a>.
        The rules are interpreted strictly:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Change type</th>
              <th>Version bump</th>
              <th>Examples</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Bug fix, docs only, internal refactor</td>
              <td>patch (<code>1.0.0</code> → <code>1.0.1</code>)</td>
              <td>Fix HMAC timing window, update README</td>
            </tr>
            <tr>
              <td>New feature, backwards-compatible</td>
              <td>minor (<code>1.0.0</code> → <code>1.1.0</code>)</td>
              <td>New HTTP endpoint, new config knob</td>
            </tr>
            <tr>
              <td>Breaking API change, config rename, schema migration that drops data</td>
              <td>major (<code>1.x.y</code> → <code>2.0.0</code>)</td>
              <td>Remove endpoint, rename env var, drop DB column</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        When in doubt, bump the higher version — over-bumping is cheap; under-bumping erodes
        trust. A new database migration alone is not a breaking change; a migration that removes
        a column is.
      </p>

      <p>Per-platform release tags follow a module-scoped convention:</p>
      <CodeBlock
        language="bash"
        code={`citadel/v1.1.0
irflow/v1.0.2
sdk/v1.0.0
apiguard/v1.3.0`}
      />

      <p>
        This lets a platform ship a security patch without forcing every other platform through
        the release cycle. It aligns with the Go monorepo convention and how{' '}
        <code>go get</code> resolves module versions.
      </p>

      <h2 id="release-types">Release types &amp; cadence</h2>
      <p>The ecosystem ships in two modes:</p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Release type</th>
              <th>Frequency</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Per-platform patch</td>
              <td>As needed</td>
              <td>Bug fixes and security patches; bypasses normal cadence for urgent security issues</td>
            </tr>
            <tr>
              <td>Per-platform minor</td>
              <td>Quarterly average</td>
              <td>New backwards-compatible features</td>
            </tr>
            <tr>
              <td>Per-platform major</td>
              <td>Annually at most</td>
              <td>Breaking changes; always accompanied by a migration guide</td>
            </tr>
            <tr>
              <td>Ecosystem release</td>
              <td>2× per year (Q2 + Q4)</td>
              <td>
                Named tag pinning a tested combination across all platforms; the
                "blessed configuration" for conservative operators
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        Ecosystem releases are coordination events, not requirements. Individual platform
        upgrades between ecosystem releases are supported via the compatibility matrix.
        Emergency security patches bypass the cadence entirely and go directly to a tagged
        version with a GitHub Security Advisory.
      </p>

      <p>
        An RC soak period precedes every final tag: 24 hours for patches, 3 business days for
        minor releases, 2 weeks for majors, and 4 weeks for ecosystem releases. The RC is
        deployed to a staging environment that mirrors production before the final tag is cut.
      </p>

      <h2 id="compatibility-matrix">Compatibility matrix</h2>
      <p>
        The <a href="https://github.com/opensecstack/opensecstack/blob/main/docs/compatibility-matrix.md" target="_blank" rel="noopener noreferrer">compatibility matrix</a>{' '}
        is the authoritative answer to "can IRFlow 1.1 talk to <a href="/docs/governance">CITADEL</a> 1.0?" — the answer is
        in the table, not in a Slack thread. It has three dimensions: per-platform pair-wise
        compatibility, ecosystem release version pins, and support windows.
      </p>

      <p>The current ecosystem releases are:</p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Ecosystem release</th>
              <th>Platforms included</th>
              <th>Highlights</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>ecosystem/v1.0.0-2026-Q2</code></td>
              <td>APIGuard, NIS2 Compass, CITADEL, IRFlow, ThreatFlow, SDK — all at v1.0.0</td>
              <td>First stable 5-platform foundation</td>
            </tr>
            <tr>
              <td><code>ecosystem/v1.1.0-2026-Q2</code></td>
              <td>
                All v1.0.0 platforms above, plus OpenScrub, CyberPath, OpenCSIRT, VertGuard
                (all v1.0.0)
              </td>
              <td>
                Full 10-platform stack; VertGuard AI-attack defence; OpenCSIRT CSAF 2.0;
                APIGuard JWT multi-secret rotation
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        The compatibility rule across all platform pairs: <strong>minor versions are forward
        and backward compatible within the same major</strong>. SDK minor versions are
        forward and backward compatible within the same major; SDK 2.0 accompanies platform
        2.0. Cross-major combinations are supported only during their explicit migration window.
      </p>

      <p>
        Some cross-platform features require minimum versions on both sides:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Feature</th>
              <th>Requires</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>HMAC-signed webhooks with per-source secrets</td>
              <td>IRFlow ≥ 1.0.0 and upstream platforms ≥ 1.0.0</td>
            </tr>
            <tr>
              <td>CITADEL MARSHAL Gate 4 AUGUR rule_03 (DATA_EXPORT block)</td>
              <td>CITADEL ≥ 1.0.0</td>
            </tr>
            <tr>
              <td>WORM chain anchor verification at <code>/worm/verify</code></td>
              <td>CITADEL ≥ 1.1.0 (planned)</td>
            </tr>
            <tr>
              <td>Overlapping-secret rotation</td>
              <td>IRFlow ≥ 1.1.0 and CITADEL ≥ 1.1.0 (both planned)</td>
            </tr>
            <tr>
              <td>Playbook auto-triggering from webhooks</td>
              <td>IRFlow ≥ 1.2.0 (planned)</td>
            </tr>
            <tr>
              <td>Multi-writer WORM chain</td>
              <td>CITADEL ≥ 2.0.0 (planned)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        HTTP APIs are versioned at the URL path level (<code>/api/v1/...</code>,{' '}
        <code>/api/v2/...</code>). When <code>/api/v2/</code> lands, <code>/api/v1/</code>{' '}
        continues to work for at least 12 months. A single server can expose multiple protocol
        versions during a transition window.
      </p>

      <div className="callout-note">
        <strong>Verifying a combination yourself:</strong> Deploy the specific platform images,
        exercise the end-to-end path (e.g. post an incident to IRFlow and verify it appears in
        the CITADEL WORM), and file a GitHub issue with label <code>compatibility-report</code>{' '}
        if you find a broken combo the matrix claims works.
      </div>

      <h2 id="support-windows">Support windows</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Category</th>
              <th>Example</th>
              <th>Support ends</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Current stable</td>
              <td>v1.1.x (latest minor)</td>
              <td>When v1.3 ships</td>
            </tr>
            <tr>
              <td>Previous stable</td>
              <td>v1.0.x</td>
              <td>12 months after v1.1 ships</td>
            </tr>
            <tr>
              <td>Older</td>
              <td>v0.9 and earlier</td>
              <td>Unsupported immediately on newer release</td>
            </tr>
            <tr>
              <td>Ecosystem release</td>
              <td><code>ecosystem/v1.0.0-2026-Q2</code></td>
              <td>12 months from the release date</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        In practice, two minor versions back always receive security fixes. Everything older is
        archived. Released versions are immutable — we never yank a published release, because
        auditors and regulators may reference a specific version. If a bug is found post-release,
        a patch release (<code>1.1.0</code> → <code>1.1.1</code>) is the fix path; downgrade
        to the previous version is always valid.
      </p>

      <h2 id="deprecation-policy">Deprecation policy</h2>
      <p>
        Any deprecated-then-removed feature passes through three phases before it disappears:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Phase</th>
              <th>Minimum duration</th>
              <th>What happens</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Supported</td>
              <td>—</td>
              <td>Default state; no removal planned</td>
            </tr>
            <tr>
              <td>Deprecated</td>
              <td>1 minor version <em>and</em> 6 calendar months (whichever is longer)</td>
              <td>
                Feature still works; runtime <code>WARN</code> log on use; docs banner;
                CHANGELOG <strong>Deprecations</strong> entry; HTTP responses carry{' '}
                <code>Deprecation</code> and <code>Sunset</code> headers
              </td>
            </tr>
            <tr>
              <td>Removed</td>
              <td>—</td>
              <td>
                Gone; requires a <strong>major version bump</strong>; migration guide published
                at <code>docs/migrations/vX-to-vY.md</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>Changes that trigger the deprecation process include:</p>
      <ul>
        <li>HTTP endpoints removed or changed (e.g. <code>DELETE /api/v1/incidents/archive</code> → <code>PATCH &#123;status:"archived"&#125;</code>)</li>
        <li>Request/response fields renamed or removed (e.g. <code>incident.criticality</code> → <code>incident.severity</code>)</li>
        <li>Config env vars renamed (e.g. <code>IRFLOW_WEBHOOK_SECRET</code> → <code>IRFLOW_WEBHOOK_&lt;SOURCE&gt;_SECRET</code>)</li>
        <li>SDK function signatures changed</li>
        <li>Event types renamed (e.g. <code>citadel.marshal.refuse</code> → <code>citadel.marshal.decision</code>)</li>
        <li>Default behaviour changes (e.g. webhook clock skew tolerance going from 10m to 5m)</li>
      </ul>

      <p>
        Internal-only changes — unexported Go functions, private modules, undocumented
        behaviours — do not require the deprecation process. The contract is with documented
        interfaces only.
      </p>

      <div className="callout-note">
        <strong>Security exceptions:</strong> A feature that is actively unsafe can be removed
        in a patch release without the full deprecation window. This requires a published
        security advisory (GitHub Security Advisory + CVE if applicable) and a replacement
        feature in the same or prior version. This exception is rare — almost every case admits
        a normal deprecation path. See the <a href="/docs/security">Security</a> page for the
        deployment-tier guarantee matrix.
      </div>

      <p>
        <strong>Experimental features</strong> — marked <code>// Experimental</code> at
        introduction — carry no deprecation obligation. They can change shape or disappear in
        any minor release. The marker must be user-visible in API docs and SDK function
        signatures. Experimental is not a loophole for insufficient design.
      </p>

      <h2 id="post-quantum-timeline">Post-quantum migration timeline</h2>
      <p>
        NIST finalised post-quantum standards (ML-KEM, ML-DSA, SLH-DSA) in August 2024.
        Quantum computers capable of breaking Ed25519 are plausibly 2030–2036. NIS3
        (expected 2030–2032) is likely to mandate PQC migration for essential entities.
        Harvest-now-decrypt-later attacks are already active. OpenSecStack is migrating the
        CITADEL chain anchor signatures so historical audits remain attestable past the quantum
        threshold.
      </p>

      <p>
        The components at risk are the <strong>Ed25519 chain anchor signatures</strong> in
        CITADEL and the <strong>X.509/ECDSA C2PA provenance</strong> in VertGuard's Module 1.
        HMAC-SHA256 webhooks and TripleHash integrity are safe — symmetric primitives have
        reduced margin but the core guarantee holds.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Year</th>
              <th>Milestone</th>
              <th>Operator burden</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>2026</td>
              <td>v1.0 shipped — Ed25519 anchors, TripleHash integrity</td>
              <td>Nothing — deploy as-is; secure against classical adversaries</td>
            </tr>
            <tr>
              <td>2026–2027</td>
              <td>v1.1 — schema agility fields (<code>signature.alg</code>, <code>digest_version</code>)</td>
              <td>Routine upgrade; no breaking change; historical entries stay valid</td>
            </tr>
            <tr>
              <td>2028</td>
              <td>
                v2.0 — hybrid signatures: every new anchor signed with both Ed25519 and
                ML-DSA-65; verifier accepts either
              </td>
              <td>
                Routine upgrade; <code>CITADEL_HYBRID_ANCHORS</code> defaults to true;
                storage grows ~0.003% per anchor
              </td>
            </tr>
            <tr>
              <td>2029</td>
              <td>v2.5 — QuintHash default (5 primitives including 2 PQ-resistant candidates)</td>
              <td>Routine upgrade; new writes adopt automatically</td>
            </tr>
            <tr>
              <td>2030</td>
              <td>v3.0 — ML-DSA becomes default; Ed25519 retained for verifying historical anchors only</td>
              <td>
                Standard NIS3-compliance upgrade; confirm no part of deployment still
                relies on Ed25519 signing
              </td>
            </tr>
            <tr>
              <td>2033</td>
              <td>v4.0 — Ed25519 signing removed; historical anchors still verifiable</td>
              <td>Confirm nothing broken; by this point the migration should be long complete</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        SDK clients verify webhook signatures (HMAC-SHA256, unaffected by quantum). The anchor
        verification path is only used when a consumer calls <code>/worm/verify</code> — and
        that endpoint returns the algorithm identifier, so SDK clients need only call the
        appropriate verification code path. Updated SDK versions ship alongside each CITADEL
        version.
      </p>
      <p>
        VertGuard's Module 1 (C2PA) is currently X.509/ECDSA-based. The C2PA specification is
        developing its own PQC migration; VertGuard will track and support hybrid C2PA manifests
        when the spec lands (~2028).
      </p>
      <p>
        For the full architectural rationale and per-tier deployment guidance, see{' '}
        <code>docs/post-quantum-roadmap.md</code> and ADR-011 (Post-Quantum Agility) in the
        opensecstack repository.
      </p>
    </DocsLayout>
  )
}
