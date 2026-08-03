import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'what-is-sinauth', label: 'What is sinauth?' },
  { id: 'oidc-endpoints', label: 'OIDC endpoints' },
  { id: 'authorization-flow', label: 'Authorization code + PKCE flow' },
  { id: 'token-format', label: 'Token format' },
  { id: 'mfa-and-social-login', label: 'MFA and social login' },
  { id: 'organizations', label: 'Organizations' },
  { id: 'sdk-clients', label: 'SDK clients' },
  { id: 'platform-integration', label: 'Platform integration' },
]

export default function IdentityPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'Identity (sinauth)']}
      toc={toc}
      editPath="IdentityPage.tsx"
      prev={{ label: 'SIN Community', path: '/docs/platforms/community' }}
      next={{ label: 'Governance (CITADEL)', path: '/docs/governance' }}
    >
      <Helmet>
        <title>Identity (sinauth) | opensecstack Docs</title>
        <meta
          name="description"
          content="sinauth is the OAuth 2.0 / OpenID Connect identity provider for opensecstack — single sign-on, PKCE, TOTP MFA, and social login shared by every platform."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/identity" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/identity" />
        <meta property="og:title" content="Identity (sinauth) | opensecstack Docs" />
        <meta
          property="og:description"
          content="sinauth is the OAuth 2.0 / OpenID Connect identity provider for opensecstack — single sign-on, PKCE, TOTP MFA, and social login shared by every platform."
        />
      </Helmet>
      <h1>Identity (sinauth)</h1>
      <p>
        <strong>sinauth</strong> is the dedicated OAuth 2.0 / OpenID Connect authorization server
        for the opensecstack ecosystem. It acts as the single identity plane for all SIN platforms
        — one account grants access to every platform via single sign-on. What Auth0 is globally,
        sinauth is for SIN.
      </p>
      <p>
        sinauth is written in pure Go with no runtime dependencies beyond PostgreSQL.
        It runs on port <code>8100</code> in the default Docker Compose topology.
        Licence: Apache 2.0.
      </p>

      <h2 id="what-is-sinauth">What is sinauth?</h2>
      <p>
        Each SIN platform is registered as an OAuth 2.0 client. When a user logs in to any
        platform, their browser is redirected to sinauth, they authenticate once, and receive
        RS256-signed ID and access tokens. Subsequent logins to other platforms within the same
        SSO session skip the login form entirely.
      </p>
      <ul>
        <li>Issues RS256-signed ID tokens and access tokens</li>
        <li>Standards: OAuth 2.0 + OpenID Connect Core 1.0</li>
        <li>Authorization code + PKCE (S256) — PKCE is mandatory for every client</li>
        <li>Refresh tokens with configurable TTL (default 30 days)</li>
        <li>TOTP multi-factor authentication (authenticator apps)</li>
        <li>Social login: Google, GitHub</li>
        <li>Admin dashboard for managing OAuth clients (platforms)</li>
      </ul>

      <div className="callout-note">
        <strong>Note:</strong> Platforms verify tokens locally against the JWKS endpoint.
        They fetch the public key set once at startup and cache it for one hour. This means
        token verification does not require a round-trip to sinauth on every request.
      </div>

      <h2 id="oidc-endpoints">OIDC endpoints</h2>
      <p>
        The production issuer is <code>https://auth.sin.to</code>. For local development the
        server listens at <code>http://localhost:8100</code>.
      </p>
      <CodeBlock
        language="bash"
        filename="OIDC integration reference"
        code={`Issuer:              https://auth.sin.to
Authorization:       https://auth.sin.to/oauth/authorize
Token:               https://auth.sin.to/oauth/token
UserInfo:            https://auth.sin.to/oauth/userinfo
JWKS:                https://auth.sin.to/.well-known/jwks.json
End session:         https://auth.sin.to/oauth/endsession
Revocation:          https://auth.sin.to/oauth/token/revoke
Introspection:       https://auth.sin.to/oauth/token/introspect
Discovery document:  https://auth.sin.to/.well-known/openid-configuration

Scopes:              openid profile email offline_access
Grant type:          authorization_code + PKCE (S256)
ID token signing:    RS256`}
      />
      <p>
        The discovery document at <code>/.well-known/openid-configuration</code> is the
        authoritative source for all endpoint URLs. Clients should read it once at startup
        and cache for one hour (<code>Cache-Control: public, max-age=3600</code>).
      </p>

      <h2 id="authorization-flow">Authorization code + PKCE flow</h2>
      <p>
        PKCE (Proof Key for Code Exchange) is mandatory for every registered client.
        The method is always <code>S256</code> — the code challenge is
        <code> BASE64URL(SHA-256(code_verifier))</code>.
      </p>
      <ol>
        <li>The client generates a random <code>code_verifier</code> and computes the <code>code_challenge</code>.</li>
        <li>The browser is redirected to <code>/oauth/authorize</code> with the challenge.</li>
        <li>sinauth validates the client and redirect URI, checks the SSO session cookie, and presents the login form if needed.</li>
        <li>After authentication (and consent on first visit), sinauth redirects back with a short-lived authorization code (5-minute TTL, single-use).</li>
        <li>The client exchanges the code for tokens at <code>/oauth/token</code>, providing the <code>code_verifier</code>. sinauth verifies <code>SHA-256(verifier) == challenge</code>.</li>
        <li>sinauth issues an RS256 access token (1-hour TTL), an RS256 ID token (5-minute TTL), and an opaque refresh token (30-day TTL, stored as a SHA-256 hash).</li>
      </ol>

      <h2 id="token-format">Token format</h2>
      <p>
        Both access tokens and ID tokens are standard JWTs signed with RS256. The JWT
        header includes a <code>kid</code> field so verifying parties can select the
        correct public key from the JWKS response.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Token type</th>
              <th>Algorithm</th>
              <th>TTL</th>
              <th>Key claims</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Access token</td>
              <td>RS256</td>
              <td>1 hour</td>
              <td><code>sub</code>, <code>iss</code>, <code>aud</code>, <code>exp</code>, <code>iat</code>, <code>kid</code></td>
            </tr>
            <tr>
              <td>ID token</td>
              <td>RS256</td>
              <td>5 minutes</td>
              <td><code>sub</code>, <code>email</code>, <code>name</code>, <code>picture</code>, <code>nonce</code></td>
            </tr>
            <tr>
              <td>Refresh token</td>
              <td>Opaque (stored as SHA-256 hash)</td>
              <td>30 days</td>
              <td>Individually revocable</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Platforms verify tokens by fetching <code>https://auth.sin.to/.well-known/jwks.json</code>,
        reading the <code>kid</code> from the JWT header, selecting the matching JWK, and
        verifying the RS256 signature. They also check <code>exp</code>, <code>iss</code>
        (<code>https://auth.sin.to</code>), and <code>aud</code> (their own
        <code> client_id</code>).
      </p>

      <h2 id="mfa-and-social-login">MFA and social login</h2>
      <p>
        sinauth supports TOTP multi-factor authentication enforced centrally — users register
        an authenticator app and every login requires the current TOTP code. Social login via
        Google and GitHub is supported alongside password-based accounts. MFA state is
        transparent to the platforms; they receive normal RS256 tokens regardless of which
        authentication method was used.
      </p>

      <h2 id="organizations">Organizations</h2>
      <p>
        sinauth recognizes two kinds of identity subject: an individual <strong>user</strong>,
        and — as of v1.1 — an <strong>organization</strong>. Organizations model government
        institutions, private companies, e-commerce businesses, and NGOs as first-class
        identities alongside the people who act on their behalf.
      </p>
      <p>
        A user can belong to one or more organizations as a member (with a role of
        <code> owner</code>, <code>admin</code>, or <code>member</code>). Membership doesn't
        change how a user signs in — the individual login flow above is untouched — but it
        unlocks the option to act <em>on behalf of</em> an organization for a given session.
        When authorizing, a client can pass an <code>organization_id</code>; if the user is a
        member, the resulting ID token and access token carry <code>org_id</code>,{' '}
        <code>org_role</code>, and <code>org_type</code> claims alongside the usual{' '}
        <code>sub</code>. Omit it, and tokens are issued exactly as they always were — this is
        additive, not a breaking change, so platforms that don't care about organizations can
        ignore the claims entirely.
      </p>
      <p>
        If a user belongs to more than one organization and doesn't specify which one, sinauth
        shows an <strong>organization picker</strong> step instead of guessing — the same way a
        consent screen appears on first login to a new platform. A single token never
        represents both an individual and an organization at once.
      </p>
      <div className="callout-note">
        <strong>Note:</strong> v1.1 covers organization membership, org-scoped token claims,
        and the org picker. Machine-to-machine credentials for organizations
        (<code>client_credentials</code>) and CITADEL-gated organization verification are
        planned for a later release and are not available yet — see{' '}
        <a href="/docs/governance">Governance (CITADEL)</a> for how governed actions work
        today.
      </div>

      <h2 id="sdk-clients">SDK clients</h2>
      <p>
        The opensecstack <a href="/docs/contracts">SDK &amp; Contracts</a> ships sinauth client helpers in Go and TypeScript. These
        implement the OIDC discovery fetch, JWKS caching, and RS256 token verification so
        platform teams do not need to re-implement them.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Language</th>
              <th>Package</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><a href="/docs/sdk/go">Go</a></td>
              <td><code>github.com/opensecstack/sdk/go/sinauth</code></td>
            </tr>
            <tr>
              <td><a href="/docs/sdk/typescript">TypeScript</a></td>
              <td><code>@opensecstack/sdk</code> (sinauth sub-module)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="platform-integration">Platform integration</h2>
      <p>
        Each SIN platform has a dedicated integration guide under
        <code> sinauth/docs/integration/</code>. The guides cover client registration,
        redirect URI configuration, scope selection, and token verification for:
        <a href="/docs/platforms/apiguard">APIGuard</a>, <a href="/docs/platforms/irflow">IRFlow</a>, <a href="/docs/platforms/nis2compass">NIS2 Compass</a>, <a href="/docs/platforms/threatflow">ThreatFlow</a>, <a href="/docs/platforms/opencsirt">OpenCSIRT</a>, <a href="/docs/platforms/cyberpath">CyberPath</a>, <a href="/docs/platforms/securelab">SecureLab</a>,
        <a href="/docs/platforms/openscrub">OpenScrub</a>, <a href="/docs/platforms/vertguard">VertGuard</a>, and the <a href="/docs/platforms/community">SIN Community</a> platform.
      </p>
      <div className="callout-note">
        <strong>Note:</strong> All end-user and operator authentication is delegated to
        sinauth over OpenID Connect. Platforms validate sinauth-issued RS256 tokens
        against the JWKS endpoint rather than minting their own user credentials.
        See <a href="/docs/governance">CITADEL</a> for the governance layer and{' '}
        <a href="/docs/architecture">Architecture</a> for how sinauth fits into
        the wider ecosystem.
      </div>
    </DocsLayout>
  )
}
