import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const genKeysCode = `# Generate RS256 key pair
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# Move keys to the expected location
mkdir -p ./keys
mv private.pem public.pem ./keys/`

const dockerCode = `# docker-compose.yml
services:
  sinauth:
    image: ghcr.io/opensecstack/sinauth:latest
    environment:
      DATABASE_URL: postgres://sinauth:secret@db/sinauth
      SINAUTH_SITE_URL: https://auth.yourdomain.com
      SINAUTH_JWT_PRIVATE_KEY_PATH: /keys/private.pem
      SINAUTH_JWT_PUBLIC_KEY_PATH: /keys/public.pem
      SINAUTH_JWT_EXPIRY: 15m
    ports:
      - "8080:8080"
    volumes:
      - ./keys:/keys:ro
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: sinauth
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: sinauth
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sinauth"]
      interval: 5s
      timeout: 5s
      retries: 5
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:`

const runCode = `# Start the stack
docker compose up -d

# Check logs
docker compose logs -f sinauth

# Admin UI is available at:
# http://localhost:8080/admin
# Default credentials: admin / changeme (set via env SINAUTH_ADMIN_PASSWORD)`

const registerClientCode = `# Register a client via REST API
curl -X POST http://localhost:8080/admin/api/clients \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_id": "my-spa",
    "name": "My Single-Page App",
    "redirect_uris": ["https://app.example.com/callback", "http://localhost:3000/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "pkce_required": true
  }'`

const toc = [
  { id: 'prerequisites', label: 'Prerequisites' },
  { id: 'step1', label: 'Step 1: Generate JWT keys' },
  { id: 'step2', label: 'Step 2: docker-compose.yml' },
  { id: 'step3', label: 'Step 3: Run & first login' },
  { id: 'step4', label: 'Step 4: Register a client' },
  { id: 'next-steps', label: 'Next steps' },
]

export default function QuickStartPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Getting Started', 'Quick Start']}
      toc={toc}
      editPath="QuickStartPage.tsx"
      prev={{ label: "Introduction", path: "/docs/intro" }}
      next={{ label: "Installation", path: "/docs/installation" }}
    >
      <h1>Quick Start</h1>

      <p>
        This guide walks you through standing up a fully functional sinauth instance in under five
        minutes using Docker Compose. By the end you will have OAuth2/OIDC endpoints, an admin
        dashboard, and a registered client ready for integration.
      </p>

      <h2 id="prerequisites">Prerequisites</h2>

      <div className="callout-note">
        <strong>Note:</strong> You need Docker 24+ with the Compose plugin and{' '}
        <code>openssl</code> on your PATH. A PostgreSQL instance is included in the Compose file —
        no separate install needed.
      </div>

      <ul>
        <li>Docker 24+ with Compose plugin</li>
        <li>
          <code>openssl</code> (pre-installed on macOS and most Linux distros)
        </li>
        <li>Ports 8080 (sinauth) and 5432 (Postgres) available</li>
      </ul>

      <h2 id="step1">Step 1: Generate JWT keys</h2>

      <p>
        sinauth signs JWTs with RS256, which requires an RSA key pair. Generate one now and store
        it in a <code>./keys</code> directory that will be mounted read-only into the container.
      </p>

      <CodeBlock code={genKeysCode} language="bash" filename="terminal" />

      <div className="callout-warning">
        <strong>Security:</strong> Never commit <code>private.pem</code> to source control. Add{' '}
        <code>keys/</code> to your <code>.gitignore</code> immediately.
      </div>

      <h2 id="step2">Step 2: docker-compose.yml</h2>

      <p>
        Create a <code>docker-compose.yml</code> in your project root. The configuration below
        runs sinauth and a dedicated Postgres instance. Adjust <code>SINAUTH_SITE_URL</code> to
        your actual domain when deploying to production.
      </p>

      <CodeBlock code={dockerCode} language="yaml" filename="docker-compose.yml" />

      <h2 id="step3">Step 3: Run & first login</h2>

      <p>
        Start the stack and wait for sinauth to print{' '}
        <code>sinauth ready</code> in the logs. The admin panel is available immediately.
      </p>

      <CodeBlock code={runCode} language="bash" filename="terminal" />

      <p>
        Open <code>http://localhost:8080/admin</code> and sign in with the default credentials.
        Change the admin password before exposing sinauth to the internet.
      </p>

      <h2 id="step4">Step 4: Register a client</h2>

      <p>
        Every application that wants to use sinauth for authentication needs a registered OAuth2
        client. You can create one through the admin UI or the REST API. Here is the API approach
        for automation:
      </p>

      <CodeBlock code={registerClientCode} language="bash" filename="terminal" />

      <p>
        After registration, copy the <code>client_id</code> into your application. For a public
        client (SPA, mobile), no <code>client_secret</code> is needed — PKCE handles the security.
      </p>

      <h2 id="next-steps">Next steps</h2>

      <ul>
        <li>
          Read the{' '}
          <a href="/docs/config">Environment Variables</a> reference to fine-tune your
          deployment.
        </li>
        <li>
          Install the{' '}
          <a href="/docs/sdk">SDK</a> for your language and start verifying tokens.
        </li>
        <li>
          Enable Social SSO by adding your Google and GitHub OAuth2 app credentials in the admin
          panel under <strong>Providers</strong>.
        </li>
        <li>
          Enable TOTP for your admin account under <strong>Security → Two-Factor Auth</strong>.
        </li>
      </ul>
    </DocsLayout>
  )
}
