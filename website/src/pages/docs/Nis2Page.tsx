import DocsLayout from './DocsLayout'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'article-21-measures', label: 'Article 21(2) measures' },
  { id: 'platform-coverage', label: 'Platform coverage table' },
  { id: 'article-23-notification', label: 'Article 23 notification' },
  { id: 'eu-ai-act', label: 'EU AI Act — VertGuard' },
  { id: 'nis3-readiness', label: 'NIS3 readiness (projected)' },
]

export default function Nis2Page() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Compliance', 'NIS2 & EU AI Act']}
      toc={toc}
      editPath="Nis2Page.tsx"
      prev={{ label: 'Rust SDK', path: '/docs/sdk/rust' }}
      next={{ label: 'Deployment', path: '/docs/deployment' }}
    >
      <h1>NIS2 &amp; EU AI Act</h1>
      <p>
        The opensecstack ecosystem is designed around the European regulatory and threat
        landscape. This page maps how the 11 platforms satisfy the security measures mandated
        by <strong>NIS2 Directive 2022/2555</strong> (Articles 21 and 23) and explains the
        additional obligations introduced by the <strong>EU AI Act (Regulation 2024/1689)</strong>,
        which intersect with <a href="/docs/platforms/vertguard">VertGuard</a> and the projected NIS3 trajectory.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        NIS2 applies to essential and important entities across the EU. It mandates appropriate
        technical and organisational security measures (Article 21) and requires notification of
        significant incidents to the national CSIRT or competent authority within defined
        deadlines (Article 23). The opensecstack ecosystem was built to provide a complete,
        evidence-generating, self-hostable implementation of these obligations.
      </p>
      <p>
        No single platform covers every measure. The ecosystem is designed so each platform is
        the <em>primary</em> evidence source for one or two measures, with secondary contributions
        across others. The combination of platforms — particularly the <a href="/docs/governance">CITADEL</a> WORM audit chain
        and <a href="/docs/platforms/nis2compass">NIS2 Compass</a> as the assessment hub — means auditors can trace every control back to
        tamper-evident, independently verifiable records.
      </p>

      <div className="callout-note">
        <strong>Scope:</strong> This page covers the ecosystem-wide NIS2 mapping. Each
        platform's own <code>nis2-mapping.md</code> (in its <code>docs/</code> folder) provides
        the full per-measure evidence package and configuration steps for that platform.
      </div>

      <h2 id="article-21-measures">Article 21(2) measures</h2>
      <p>
        Article 21(2) lists ten categories of security measure that essential and important
        entities must implement:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Ref</th>
              <th>Measure</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>(a)</td>
              <td>Risk analysis and information system security policies</td>
            </tr>
            <tr>
              <td>(b)</td>
              <td>Incident handling</td>
            </tr>
            <tr>
              <td>(c)</td>
              <td>Business continuity and crisis management</td>
            </tr>
            <tr>
              <td>(d)</td>
              <td>Supply chain security</td>
            </tr>
            <tr>
              <td>(e)</td>
              <td>
                Security in network and information systems acquisition, development and
                maintenance, including vulnerability handling and disclosure
              </td>
            </tr>
            <tr>
              <td>(f)</td>
              <td>
                Policies and procedures to assess the effectiveness of cybersecurity
                risk-management measures
              </td>
            </tr>
            <tr>
              <td>(g)</td>
              <td>Basic cyber hygiene practices and cybersecurity training</td>
            </tr>
            <tr>
              <td>(h)</td>
              <td>Policies and procedures regarding the use of cryptography and encryption</td>
            </tr>
            <tr>
              <td>(i)</td>
              <td>Human resources security, access control policies and asset management</td>
            </tr>
            <tr>
              <td>(j)</td>
              <td>
                Use of multi-factor authentication or continuous authentication solutions
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="platform-coverage">Platform coverage table</h2>
      <p>
        The table below maps each platform to the measures it primarily covers and any secondary
        contributions. <strong>Primary</strong> means the platform generates the main compliance
        evidence for that measure. <strong>Secondary</strong> means the platform contributes
        supporting evidence but is not the main record.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>Primary measure(s)</th>
              <th>Secondary measures</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong><a href="/docs/platforms/nis2compass">NIS2 Compass</a></strong></td>
              <td>(a) (b) (c) — all measures (assessment hub)</td>
              <td>All</td>
              <td>
                Central compliance evidence store; integrates evidence from all other platforms
                and manages Art. 23 notification records
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/irflow">IRFlow</a></strong></td>
              <td>(b) Incident handling</td>
              <td>(a) (c) (d) (e) (f) (h) (i) (j)</td>
              <td>
                Core incident lifecycle; WORM-anchored timeline; auto-notifies NIS2 Compass
                within 24-hour window for P1/P2 incidents
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/apiguard">APIGuard</a></strong></td>
              <td>(e) Vulnerability handling</td>
              <td>(a) (d) (h) (i) (j)</td>
              <td>
                OWASP API Top 10 coverage; scan reports constitute technical evidence for
                Art. 21(2)(e); CI/CD integration via SARIF export
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/threatflow">ThreatFlow</a></strong></td>
              <td>(b) (d) (e)</td>
              <td>(h)</td>
              <td>
                IOC enrichment for incidents; STIX 2.1 exports for NIS2 Compass; tracks
                supply-chain IOCs; monitors cryptographic vulnerability indicators
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/openscrub">OpenScrub</a></strong></td>
              <td>(b) (c) Availability &amp; DDoS response</td>
              <td>(a) (e)</td>
              <td>
                XDP/eBPF DDoS mitigation; emits structured events to CITADEL ARBITER for
                Art. 23 aggregation on High/Critical attack events
              </td>
            </tr>
            <tr>
              <td><strong>VertGuard</strong></td>
              <td>(e) AI-attack defence</td>
              <td>(a) (b) (d) (f) (h)</td>
              <td>
                Prompt injection, deepfake, synthetic identity, AI phishing detection;
                MITRE ATLAS categorisation; WORM-anchored detections; also maps to EU AI Act
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/opencsirt">OpenCSIRT</a></strong></td>
              <td>(b) CSIRT operations</td>
              <td>(d) (e)</td>
              <td>
                TAXII 2.1 / CSAF 2.0; peer federation; Art. 23 notification support;
                WORM emission on advisory publication
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/cyberpath">CyberPath</a></strong></td>
              <td>(g) Cyber hygiene &amp; training</td>
              <td>(b)</td>
              <td>
                Docker/Wasm security labs; generates training completion records usable as
                Art. 21(2)(g) evidence
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/platforms/securelab">SecureLab</a></strong></td>
              <td>(f) Effectiveness assessment</td>
              <td>(b) (e)</td>
              <td>
                Attack simulation and detection validation; scenario results feed
                effectiveness metrics
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/governance">CITADEL</a></strong></td>
              <td>(h) Cryptography; (i) Access control</td>
              <td>All (governance layer)</td>
              <td>
                <a href="/docs/citadel/marshal">MARSHAL</a> 5-gate policy engine; <a href="/docs/citadel/worm">WORM</a> audit chain with TripleHash integrity
                (SHA-256 + SHA-512 + BLAKE3) and Ed25519 anchors; <a href="/docs/citadel/sod">SoD</a> enforcement across
                all platforms
              </td>
            </tr>
            <tr>
              <td><strong><a href="/docs/identity">sinauth</a></strong></td>
              <td>(j) MFA &amp; authenticated access</td>
              <td>(i)</td>
              <td>
                OAuth 2.0 / OIDC; PKCE; RS256 + JWKS; TOTP MFA; single sign-on for all
                platform operators
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>Evidence chain:</strong> For an auditor tracing a single incident, the evidence
        path is: IRFlow incident row → CITADEL WORM entries (one per action) → Ed25519 chain
        anchor signatures (tamper-evident) → Article 23 notification record in NIS2 Compass →
        NIS2 Compass assessment linking Art. 21(2)(b). Each step is independently verifiable
        even if IRFlow's database were corrupted.
      </div>

      <h2 id="article-23-notification">Article 23 notification</h2>
      <p>
        Article 23 requires essential entities to notify the national CSIRT or competent
        authority of significant incidents within strict deadlines. The ecosystem automates the
        24-hour early-warning path for the highest-severity incidents.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Phase</th>
              <th>Deadline</th>
              <th>Ecosystem feature</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Early warning</td>
              <td>24 hours after becoming aware</td>
              <td>
                IRFlow auto-pushes to NIS2 Compass <code>/api/v1/notifications</code> on
                creation of any P1/P2 incident. The notification runs on a detached goroutine
                so a slow Compass API never blocks incident creation.
              </td>
            </tr>
            <tr>
              <td>Full notification</td>
              <td>72 hours</td>
              <td>
                Manual today; IRFlow v1.1 adds an upgrade-notification path that resubmits
                the incident timeline. OpenScrub emits severity High/Critical attack events to
                CITADEL ARBITER for aggregation.
              </td>
            </tr>
            <tr>
              <td>Final report</td>
              <td>1 month</td>
              <td>
                NIS2 Compass assessment export. IRFlow and ThreatFlow records are referenced
                as evidence artefacts.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        ThreatFlow also participates in the 24-hour path: when IOC correlation raises a P1/P2
        incident above NIS2 significance thresholds, ThreatFlow sets the{' '}
        <code>nis2_notify_required</code> flag on the IRFlow incident via the incidents API,
        triggering the same notification goroutine.
      </p>
      <p>
        A successful notification records <code>nis2_notified_at</code> on the IRFlow incident
        row. The metric <code>irflow_governance_calls_total&#123;target="nis2",result="failure"&#125;</code>{' '}
        surfaces notification failures for operator alerting.
      </p>

      <h2 id="eu-ai-act">EU AI Act — VertGuard</h2>
      <p>
        The EU AI Act (Regulation 2024/1689) entered force in August 2024 with staggered
        applicability through 2027. It applies to VertGuard in two ways:
      </p>
      <ul>
        <li>
          <strong>VertGuard as AI system operator (low-risk tier):</strong> VertGuard itself
          uses ML for Modules 1, 2, and 5. This makes it an AI system with obligations under
          the Act.
        </li>
        <li>
          <strong>VertGuard as a defence tool for AI system operators:</strong> Organisations
          deploying LLM-powered applications are themselves AI Act-scoped. VertGuard provides
          the technical controls for prompt-injection blocking (Art. 14 human oversight), detection
          logging (Art. 12 record-keeping), and AI-attack defence (Art. 15 cybersecurity).
        </li>
      </ul>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>EU AI Act article</th>
              <th>Obligation</th>
              <th>VertGuard compliance</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Art. 9</td>
              <td>Risk management system</td>
              <td>Documented in SECURITY.md threat model; Module 3 implements the runnable policy</td>
            </tr>
            <tr>
              <td>Art. 10</td>
              <td>Data governance</td>
              <td>Model + dataset registries with provenance and SHA-256 checksums</td>
            </tr>
            <tr>
              <td>Art. 11</td>
              <td>Technical documentation</td>
              <td>Full model cards in <code>docs/ml-models-reference.md</code></td>
            </tr>
            <tr>
              <td>Art. 12</td>
              <td>Record-keeping (logging)</td>
              <td>All detections WORM-logged via CITADEL from v0.1</td>
            </tr>
            <tr>
              <td>Art. 13</td>
              <td>Transparency</td>
              <td>
                Per-detection confidence exposed; deterministic patterns separated from ML
                classification; C2PA signer chain exposed per detection
              </td>
            </tr>
            <tr>
              <td>Art. 14</td>
              <td>Human oversight</td>
              <td>Prompt-injection blocking + appeals process via CITADEL MARSHAL gate</td>
            </tr>
            <tr>
              <td>Art. 15</td>
              <td>Accuracy, robustness, cybersecurity</td>
              <td>
                Published accuracy benchmarks; false-positive test corpus; Module 3 is the
                primary AI security control
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="nis3-readiness">NIS3 readiness (projected)</h2>
      <p>
        NIS3 does not yet exist as a formal instrument. Based on NIS2 Article 41's review
        schedule, the Commission will publish a review by October 2027; a legislative proposal
        is plausible for 2028–2029, with adoption 2030–2031 and transposition 2032–2033.
      </p>
      <p>
        NIS3 is expected to move beyond NIS2's generic "network and information systems security"
        language and introduce explicit obligations for AI-attack defence, AI supply-chain
        provenance, cross-CSIRT AI-threat sharing, and post-quantum cryptographic migration.
        The following table shows where the ecosystem stands today against projected NIS3
        requirements:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Projected NIS3 requirement</th>
              <th>VertGuard / ecosystem today</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>AI-system input attack defence (prompt injection, jailbreaks)</td>
              <td>Module 3 — pattern + ML classifier (Phase 4.1/4.2)</td>
              <td>Covered</td>
            </tr>
            <tr>
              <td>Deepfake / synthetic media detection</td>
              <td>Module 1 — C2PA in v0.1; ML deepfake in v0.5 (2027)</td>
              <td>Partial</td>
            </tr>
            <tr>
              <td>AI-generated phishing detection</td>
              <td>Module 2 — planned v0.5 (2027 Q3)</td>
              <td>Planned</td>
            </tr>
            <tr>
              <td>ML supply-chain provenance (model + dataset)</td>
              <td>Model registry + SHA-256 checksums; dataset registry</td>
              <td>Partial</td>
            </tr>
            <tr>
              <td>Cryptographic evidence chain (tamper-evident)</td>
              <td>TripleHash + CITADEL WORM + Ed25519 anchor signatures</td>
              <td>Covered</td>
            </tr>
            <tr>
              <td>Standardised AI-IOC format (STIX + MITRE ATLAS)</td>
              <td>ThreatFlow STIX-compatible bundle; Module 4 ATLAS tagging</td>
              <td>Covered</td>
            </tr>
            <tr>
              <td>Post-quantum cryptographic migration mandate</td>
              <td>
                Ecosystem PQ roadmap: hybrid Ed25519 + ML-DSA in v2.0 (2028);
                PQ-default in v3.0 (2030)
              </td>
              <td>Planned</td>
            </tr>
            <tr>
              <td>AI-agent governance (human oversight, audit trail)</td>
              <td>CITADEL MARSHAL gate; every AI-initiated action reviewable</td>
              <td>Partial</td>
            </tr>
            <tr>
              <td>Cross-CSIRT AI-threat sharing</td>
              <td>
                Module 4 ATLAS-tagged IOCs via ThreatFlow; OpenCSIRT federation Phase 3
                (not yet implemented)
              </td>
              <td>Partial</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>Deployers in 2026</strong> are not "NIS3-compliant" — NIS3 does not exist.
        They are <strong>NIS2 Article 21(e)-aligned</strong> and accumulating the evidence
        chain that NIS3 will require. The CITADEL WORM log retains evidence from v0.1 onward;
        setting a 7-year retention window now ensures that chain covers the full NIS3 evidence
        horizon before the directive is even ratified.
      </div>
    </DocsLayout>
  )
}
