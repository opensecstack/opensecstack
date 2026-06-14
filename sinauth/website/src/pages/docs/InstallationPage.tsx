import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const binaryCode = `# Linux (amd64)
curl -LO https://github.com/opensecstack/sinauth/releases/latest/download/sinauth_linux_amd64.tar.gz
tar -xzf sinauth_linux_amd64.tar.gz
sudo mv sinauth /usr/local/bin/

# macOS (Apple Silicon)
curl -LO https://github.com/opensecstack/sinauth/releases/latest/download/sinauth_darwin_arm64.tar.gz
tar -xzf sinauth_darwin_arm64.tar.gz
sudo mv sinauth /usr/local/bin/

# Verify
sinauth --version`

const dockerPullCode = `# Latest stable
docker pull ghcr.io/opensecstack/sinauth:latest

# Pinned version
docker pull ghcr.io/opensecstack/sinauth:0.9.2`

const dockerRunCode = `docker run -d \\
  --name sinauth \\
  -e DATABASE_URL="postgres://sinauth:secret@host.docker.internal/sinauth" \\
  -e SINAUTH_SITE_URL="http://localhost:8080" \\
  -e SINAUTH_JWT_PRIVATE_KEY_PATH="/keys/private.pem" \\
  -e SINAUTH_JWT_PUBLIC_KEY_PATH="/keys/public.pem" \\
  -e SINAUTH_ADMIN_PASSWORD="changeme" \\
  -v $(pwd)/keys:/keys:ro \\
  -p 8080:8080 \\
  ghcr.io/opensecstack/sinauth:latest`

const fromSourceCode = `# Requirements: Go 1.22+, Node.js 20+, pnpm
git clone https://github.com/opensecstack/sinauth.git
cd sinauth

# Build the admin UI
cd web && pnpm install && pnpm build && cd ..

# Build the Go binary (embeds web/dist at compile time)
cd api && go build -o sinauth ./cmd/server && cd ..

# Run
./api/sinauth`

const healthCheckCode = `curl http://localhost:8080/health
# {"status":"ok","version":"0.9.2","db":"ok"}`

const toc = [
  { id: 'methods', label: 'Install methods' },
  { id: 'binary', label: 'Pre-built binary' },
  { id: 'docker', label: 'Docker image' },
  { id: 'source', label: 'From source' },
  { id: 'verify', label: 'Verify the installation' },
]

export default function InstallationPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Getting Started', 'Installation']}
      toc={toc}
      editPath="InstallationPage.tsx"
      prev={{ label: 'Quick Start', path: '/docs/quickstart' }}
      next={{ label: 'Environment Vars', path: '/docs/config' }}
    >
      <h1>Installation</h1>

      <p>
        sinauth ships as a single self-contained binary that embeds the admin UI. Choose the
        method that fits your deployment target.
      </p>

      <h2 id="methods">Install methods</h2>

      <div className="callout-note">
        <strong>Recommended for production:</strong> Use the Docker image with Docker Compose or
        Kubernetes. The pre-built binary is ideal for bare-metal. Building from source is for
        contributors or unreleased builds.
      </div>

      <h2 id="binary">Pre-built binary</h2>

      <p>
        Binaries for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64) are
        published on the GitHub Releases page. Each release includes a SHA-256 checksum file.
      </p>

      <CodeBlock code={binaryCode} language="bash" filename="terminal" />

      <div className="callout-warning">
        <strong>macOS Gatekeeper:</strong> The first run may be blocked. Go to{' '}
        <strong>System Settings → Privacy & Security</strong> and allow the binary, or run{' '}
        <code>xattr -d com.apple.quarantine sinauth</code> after download.
      </div>

      <h2 id="docker">Docker image</h2>

      <p>
        The official image is published to the GitHub Container Registry. It is based on{' '}
        <code>gcr.io/distroless/static</code> — no shell, no package manager, minimal attack
        surface.
      </p>

      <CodeBlock code={dockerPullCode} language="bash" filename="terminal" />

      <p>
        For a full production-grade setup with Postgres, use the Docker Compose file in the{' '}
        <a href="/docs/quickstart" style={{ color: '#6366f1' }}>Quick Start</a> guide. For a
        quick local smoke-test:
      </p>

      <CodeBlock code={dockerRunCode} language="bash" filename="terminal" />

      <div className="callout-note">
        <strong>Keys required:</strong> The container needs RSA key files mounted at the paths
        set by <code>SINAUTH_JWT_PRIVATE_KEY_PATH</code> and{' '}
        <code>SINAUTH_JWT_PUBLIC_KEY_PATH</code>. See{' '}
        <a href="/docs/quickstart#step1" style={{ color: '#6366f1' }}>Quick Start Step 1</a>{' '}
        for key generation.
      </div>

      <h2 id="source">From source</h2>

      <p>
        Building from source requires Go 1.22+ and Node.js 20+ with pnpm. The binary embeds the
        compiled React admin UI from <code>web/dist</code> at compile time via Go's{' '}
        <code>embed</code> package.
      </p>

      <CodeBlock code={fromSourceCode} language="bash" filename="terminal" />

      <div className="callout-note">
        <strong>Development mode:</strong> Run <code>pnpm dev</code> inside <code>web/</code>{' '}
        alongside the Go server (set <code>APP_ENV=development</code>) to get hot-reloading for
        the admin UI. The API server proxies <code>localhost:5173</code> in development mode.
      </div>

      <h2 id="verify">Verify the installation</h2>

      <p>
        Once sinauth is running, confirm it is healthy:
      </p>

      <CodeBlock code={healthCheckCode} language="bash" filename="terminal" />

      <p>
        Open <code>http://localhost:8080/.well-known/openid-configuration</code> to inspect the
        OIDC discovery document. The admin UI is at <code>http://localhost:8080/admin</code>.
      </p>
    </DocsLayout>
  )
}
