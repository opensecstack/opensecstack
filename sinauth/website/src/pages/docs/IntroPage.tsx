import DocsLayout from './DocsLayout'

const toc = [
  { id: 'what-is-sinauth', label: 'What is sinauth?' },
  { id: 'features', label: 'Features' },
  { id: 'architecture', label: 'Architecture' },
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
      <h1>Introduction</h1>
      <p>
        <strong>sinauth</strong> is an open-source OAuth2/OIDC identity provider built for modern
        multi-platform architectures. It gives your applications a single, secure authentication
        layer with support for PKCE, Social SSO, TOTP, RBAC, SAML 2.0, and a triple-hash WORM
        audit chain.
      </p>

      <h2 id="what-is-sinauth">What is sinauth?</h2>
      <p>
        sinauth acts as the central identity hub for all platforms in the OpenSecStack ecosystem —
        and any application that speaks OAuth2/OIDC. Instead of each application managing its own
        users and sessions, sinauth handles authentication once and issues signed JWTs (RS256) that
        every service can verify independently.
      </p>
      <p>
        It is self-hosted, open-source (Apache 2.0), and ships as a single Go binary with a Postgres
        backend. There is no SaaS component, no telemetry, and no vendor lock-in.
      </p>

      <h2 id="features">Features</h2>
      <ul>
        <li><strong>Authorization Code + PKCE</strong> — RFC 7636, no client secrets needed for public clients</li>
        <li><strong>Social SSO</strong> — Google and GitHub out of the box, pluggable provider architecture</li>
        <li><strong>TOTP &amp; WebAuthn</strong> — RFC 6238 authenticator apps and hardware keys</li>
        <li><strong>RBAC &amp; Groups</strong> — fine-grained role-based access with policy engine</li>
        <li><strong>SAML 2.0 SP</strong> — enterprise IdP federation (AD FS, Okta, Entra ID)</li>
        <li><strong>Triple-Hash Audit</strong> — SHA-256 + SHA-512 + BLAKE3 WORM chain</li>
        <li><strong>Popup SSO</strong> — Gjirafa/Google-style login popup via TypeScript SDK</li>
        <li><strong>Admin UI</strong> — built-in React dashboard for users, clients, sessions, audit log</li>
      </ul>

      <h2 id="architecture">Architecture</h2>
      <p>
        sinauth is a single Go service that exposes:
      </p>
      <ul>
        <li><strong>REST API</strong> — <code>/api/v1/auth/*</code> for authentication, <code>/api/v1/admin/*</code> for management</li>
        <li><strong>OIDC Discovery</strong> — <code>/.well-known/openid-configuration</code></li>
        <li><strong>JWKS endpoint</strong> — <code>/.well-known/jwks.json</code> for public key distribution</li>
        <li><strong>OAuth2 endpoints</strong> — <code>/oauth/authorize</code>, <code>/oauth/login</code></li>
        <li><strong>Admin UI</strong> — served as a React SPA from <code>/</code></li>
      </ul>
      <p>
        All tokens are RS256 JWTs. Client applications verify tokens locally using the public key
        from JWKS — no round-trip to sinauth on every request.
      </p>

      <h2 id="next-steps">Next steps</h2>
      <p>
        Ready to get sinauth running? Head to the <a href="/docs/quickstart" style={{ color: '#6366f1' }}>Quick Start</a> guide
        to be up in under 5 minutes.
      </p>
    </DocsLayout>
  )
}
