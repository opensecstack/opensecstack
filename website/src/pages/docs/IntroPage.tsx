import DocsLayout from './DocsLayout'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'what-is-opensecstack', label: 'What is opensecstack?' },
  { id: 'the-ecosystem', label: 'The ecosystem' },
  { id: 'two-cross-cutting-layers', label: 'Two cross-cutting layers' },
  { id: 'next-steps', label: 'Next steps' },
]

export default function IntroPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Getting Started', 'Introduction']}
      toc={toc}
      editPath="IntroPage.tsx"
      next={{ label: 'Quick Start', path: '/docs/quickstart' }}
    >
      <Helmet>
        <title>Introduction | opensecstack Docs</title>
        <meta
          name="description"
          content="What opensecstack is: 11 open-source security platforms, the sinauth identity layer, and CITADEL cryptographic governance, connected through typed SDK contracts."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/intro" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/intro" />
        <meta property="og:title" content="Introduction | opensecstack Docs" />
        <meta
          property="og:description"
          content="What opensecstack is: 11 open-source security platforms, the sinauth identity layer, and CITADEL cryptographic governance, connected through typed SDK contracts."
        />
      </Helmet>
      <h1>Introduction</h1>
      <p>
        <strong>opensecstack</strong> (SIN — Security Intelligence Network) is an open-source
        cybersecurity ecosystem for Europe and beyond: <strong>11 integrated security platforms</strong>,
        a single sign-on <strong>identity layer</strong> (sinauth), and a cryptographic
        <strong> governance layer</strong> (CITADEL), all connected through typed SDK contracts and
        an immutable audit trail.
      </p>

      <h2 id="what-is-opensecstack">What is opensecstack?</h2>
      <p>
        It is built for the European regulatory and threat landscape — NIS2 compliance, API
        security, incident response, threat intelligence, AI-attack defence, and security
        operations. Every platform shares the same SDK contracts, every privileged action flows
        into the same governance layer, and every deployment can be self-hosted with zero vendor
        lock-in.
      </p>
      <p>
        The software is open source under <strong>Apache-2.0</strong> (tool platforms) and
        <strong> AGPL-3.0</strong> (governance platforms). There is no SaaS requirement and no
        telemetry.
      </p>

      <h2 id="the-ecosystem">The ecosystem</h2>
      <p>The 11 platforms cover the security lifecycle:</p>
      <ul>
        <li><strong><a href="/docs/platforms/apiguard">APIGuard</a></strong> — API security testing (OWASP API Top 10)</li>
        <li><strong><a href="/docs/platforms/nis2compass">NIS2 Compass</a></strong> — NIS2 Article 21/23 compliance</li>
        <li><strong><a href="/docs/platforms/irflow">IRFlow</a></strong> — incident response orchestration</li>
        <li><strong><a href="/docs/platforms/threatflow">ThreatFlow</a></strong> — threat intelligence (STIX 2.1, MITRE ATT&amp;CK)</li>
        <li><strong><a href="/docs/platforms/openscrub">OpenScrub</a></strong> — DDoS mitigation (XDP/eBPF)</li>
        <li><strong><a href="/docs/platforms/cyberpath">CyberPath</a></strong> — security training (Docker/Wasm labs)</li>
        <li><strong><a href="/docs/platforms/securelab">SecureLab</a></strong> — attack simulation &amp; detection validation</li>
        <li><strong><a href="/docs/platforms/opencsirt">OpenCSIRT</a></strong> — CSIRT operations (TAXII 2.1, CSAF 2.0)</li>
        <li><strong><a href="/docs/platforms/vertguard">VertGuard</a></strong> — AI-attack defence (prompt injection, deepfake, MITRE ATLAS)</li>
        <li><strong><a href="/docs/platforms/community">SIN Community</a></strong> — developer knowledge hub</li>
        <li><strong><a href="/docs/identity">sinauth</a></strong> — OAuth 2.0 / OIDC identity provider</li>
      </ul>

      <h2 id="two-cross-cutting-layers">Two cross-cutting layers</h2>
      <p>
        Beneath the platforms sit two layers that everything depends on:
      </p>
      <ul>
        <li>
          <strong>sinauth</strong> — the identity layer. Every platform delegates user and operator
          authentication to it over OpenID Connect (single sign-on, RS256 + JWKS, PKCE, TOTP MFA).
        </li>
        <li>
          <strong><a href="/docs/governance">CITADEL</a></strong> — the governance layer. Every privileged action is evaluated by
          the MARSHAL 5-gate engine and recorded in an append-only WORM audit chain with TripleHash
          integrity (SHA-256 + SHA-512 + BLAKE3) and Ed25519 anchors.
        </li>
      </ul>

      <div className="callout-note">
        <strong>Note:</strong> The platforms communicate only through the typed
        <code> opensecstack/sdk</code> contracts — never ad-hoc payloads. See
        <a href="/docs/contracts"> SDK &amp; Contracts</a>.
      </div>

      <h2 id="next-steps">Next steps</h2>
      <p>
        Ready to run the stack? Head to the <a href="/docs/quickstart">Quick Start</a> to bring up
        the full ecosystem with Docker Compose in a few minutes, or read the
        <a href="/docs/architecture"> Architecture overview</a> first.
      </p>
    </DocsLayout>
  )
}
