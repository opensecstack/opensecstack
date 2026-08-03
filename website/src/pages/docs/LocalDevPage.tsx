import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'prerequisites', label: 'Prerequisites' },
  { id: 'cloning-the-repo', label: 'Cloning the repo' },
  { id: 'full-stack-hot-reload', label: 'Full-stack hot-reload workflow' },
  { id: 'single-platform', label: 'Running a single platform' },
  { id: 'without-docker', label: 'Running without Docker' },
  { id: 'env-vars', label: 'Environment variables' },
  { id: 'common-tasks', label: 'Common dev tasks' },
  { id: 'ide-setup', label: 'IDE setup' },
  { id: 'troubleshooting', label: 'Troubleshooting' },
]

export default function LocalDevPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Getting Started', 'Local Development']}
      toc={toc}
      editPath="LocalDevPage.tsx"
      prev={{ label: 'Installation', path: '/docs/installation' }}
      next={{ label: 'Overview', path: '/docs/architecture' }}
    >
      <Helmet>
        <title>Local Development | opensecstack Docs</title>
        <meta
          name="description"
          content="Run the opensecstack ecosystem locally — cloning the repo, full-stack or single-platform hot reload, working without Docker, and IDE setup for Go, Rust, TypeScript, and Python."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/local-dev" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/local-dev" />
        <meta property="og:title" content="Local Development | opensecstack Docs" />
        <meta
          property="og:description"
          content="Run the opensecstack ecosystem locally — cloning the repo, full-stack or single-platform hot reload, working without Docker, and IDE setup for Go, Rust, TypeScript, and Python."
        />
      </Helmet>
      <h1>Local Development</h1>
      <p>
        This guide walks through everything needed to run the opensecstack ecosystem on your local
        machine — cloning the repo, starting the full stack or a single platform with hot-reload,
        working without Docker, and configuring your editor for Go, Rust, TypeScript, and Python.
      </p>

      <h2 id="prerequisites">Prerequisites</h2>
      <p>
        Install the following tools before cloning the repo. For full environment requirements
        and alternative install paths see <a href="/docs/installation">Installation</a>.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Version</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Go</td>
              <td>1.22+</td>
              <td>Backend services, CLI</td>
            </tr>
            <tr>
              <td>Rust (stable)</td>
              <td>1.76+</td>
              <td>Parsers, analysers, crypto</td>
            </tr>
            <tr>
              <td>Node.js LTS</td>
              <td>20+</td>
              <td>React dashboards</td>
            </tr>
            <tr>
              <td>Python</td>
              <td>3.12+</td>
              <td>Reports, data processing</td>
            </tr>
            <tr>
              <td>Docker</td>
              <td>24+</td>
              <td>Local stack and test targets</td>
            </tr>
            <tr>
              <td>Docker Compose</td>
              <td>2.24+</td>
              <td>Orchestration (included with Docker Desktop)</td>
            </tr>
            <tr>
              <td>golangci-lint</td>
              <td>latest</td>
              <td>Go linting</td>
            </tr>
            <tr>
              <td>cargo-nextest</td>
              <td>latest</td>
              <td>Faster Rust tests (<code>cargo install cargo-nextest</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="cloning-the-repo">Cloning the repo</h2>
      <CodeBlock
        language="bash"
        code={`git clone https://github.com/opensecstack/opensecstack
cd opensecstack`}
      />
      <p>
        The repository is a monorepo. Each of the 11 platforms lives in its own top-level
        directory (<code>apiguard/</code>, <code>nis2compass/</code>, etc.). Shared SDK contracts
        are in <code>sdk/</code>, CITADEL governance in <code>.citadel/</code>, and the ecosystem
        website in <code>website/</code>. For a map of how all components relate, see the{' '}
        <a href="/docs/architecture">Architecture overview</a>.
      </p>

      <h2 id="full-stack-hot-reload">Full-stack hot-reload workflow</h2>
      <p>
        The dev Docker Compose file mounts source directories as volumes so that most code changes
        are picked up without rebuilding the container image.
      </p>
      <CodeBlock
        language="bash"
        code={`# From the repo root — starts all services
make dev

# Verify the API is up
curl http://localhost:8080/api/v1/health
# → {"status":"ok"}

# Open the dashboard
# http://localhost:3000`}
      />
      <p>Hot-reload behaviour per language:</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Language</th>
              <th>Tool</th>
              <th>Behaviour</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Go</td>
              <td><code>air</code></td>
              <td>Automatic live reload on file save</td>
            </tr>
            <tr>
              <td>React / TypeScript</td>
              <td>Vite HMR</td>
              <td>Instant in-browser hot module replacement</td>
            </tr>
            <tr>
              <td>Rust</td>
              <td>—</td>
              <td>Compiled language — run <code>cargo build</code> manually after changes</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        The full stack starts: <strong><a href="/docs/platforms/apiguard">APIGuard</a> API</strong> on port 8080,{' '}
        <strong>Dashboard</strong> on port 3000, <strong>PostgreSQL</strong> on 5432, and{' '}
        <strong>Redis</strong> on 6379.
      </p>

      <h2 id="single-platform">Running a single platform</h2>
      <p>
        You do not need to start the entire stack to work on one platform. Each platform directory
        contains its own <code>Makefile</code> and <code>.env.example</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`# Example: APIGuard only
cd apiguard
cp .env.example .env   # Edit with your values
make dev`}
      />
      <p>
        Replace <code>apiguard</code> with the directory name of the platform you are working on
        (e.g. <code>nis2compass</code>, <code>threatflow</code>, <code>opencsirt</code>).
      </p>

      <h2 id="without-docker">Running without Docker</h2>
      <p>
        If you prefer to run services directly on the host, start PostgreSQL and Redis first (or
        run only those two containers), then launch each component individually.
      </p>
      <CodeBlock
        language="bash"
        code={`# 1. Start PostgreSQL and Redis via Docker (or use local installs)
docker run -d --name pg -p 5432:5432 \\
  -e POSTGRES_USER=opensecstack \\
  -e POSTGRES_PASSWORD=changeme \\
  -e POSTGRES_DB=opensecstack \\
  postgres:16-alpine

docker run -d --name redis -p 6379:6379 redis:7-alpine

# 2. Run database migrations
cd apiguard && make migrate

# 3. Start the Go API server
cd apiguard && go run ./cmd/

# 4. Start the React dashboard (separate terminal)
cd apiguard/web && npm install && npm run dev

# 5. Build Rust components
cd apiguard/rust && cargo build --release`}
      />

      <h2 id="env-vars">Environment variables</h2>
      <p>
        Copy <code>.env.example</code> to <code>.env</code> in the platform directory. The
        following variables are required for APIGuard; every platform has its own set documented
        in <code>platform/docs/configuration.md</code>.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Variable</th>
              <th>Required</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>APIGUARD_DB_URL</code></td>
              <td>Yes</td>
              <td>PostgreSQL connection string</td>
            </tr>
            <tr>
              <td><code>APIGUARD_JWT_SECRET</code></td>
              <td>Yes</td>
              <td>JWT signing key (minimum 32 characters)</td>
            </tr>
            <tr>
              <td><code>APIGUARD_PORT</code></td>
              <td>No</td>
              <td>HTTP listen port (default <code>8080</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="callout-note">
        <strong>CITADEL variables:</strong> If your platform is configured to emit governance
        events, you will also need <code>CITADEL_API_URL</code> and <code>CITADEL_API_KEY</code>.
        Leave these unset (or set <code>CITADEL_DRY_RUN=true</code>) for local development
        without a running CITADEL instance. See <a href="/docs/citadel-integration">CITADEL
        Integration</a> for details.
      </div>

      <h2 id="common-tasks">Common dev tasks</h2>
      <CodeBlock
        language="bash"
        code={`# Run all tests
make test

# Run linters
make lint

# Format code
make fmt

# Run a sample scan against VAmPI (APIGuard)
cd apiguard && make scan-example

# Start test targets (VAmPI, crAPI)
cd apiguard && docker compose -f docker-compose.test.yml up -d`}
      />

      <h2 id="ide-setup">IDE setup</h2>

      <h3>VS Code (recommended)</h3>
      <p>
        The fastest path is the built-in Dev Container: open the <code>opensecstack/</code> folder
        in VS Code and click <strong>"Reopen in Container"</strong> when prompted. All tools are
        pre-installed.
      </p>
      <p>For a manual setup, install these extensions:</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Extension</th>
              <th>ID</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Go</td>
              <td><code>golang.go</code></td>
              <td>Go language support, debugging, testing</td>
            </tr>
            <tr>
              <td>rust-analyzer</td>
              <td><code>rust-lang.rust-analyzer</code></td>
              <td>Rust language support, completion, Clippy</td>
            </tr>
            <tr>
              <td>Python</td>
              <td><code>ms-python.python</code></td>
              <td>Python language support</td>
            </tr>
            <tr>
              <td>ESLint</td>
              <td><code>dbaeumer.vscode-eslint</code></td>
              <td>JavaScript / TypeScript linting</td>
            </tr>
            <tr>
              <td>Prettier</td>
              <td><code>esbenp.prettier-vscode</code></td>
              <td>Code formatting (React / TS)</td>
            </tr>
            <tr>
              <td>Docker</td>
              <td><code>ms-azuretools.vscode-docker</code></td>
              <td>Docker file support</td>
            </tr>
            <tr>
              <td>Even Better TOML</td>
              <td><code>tamasfe.even-better-toml</code></td>
              <td>Cargo.toml support</td>
            </tr>
            <tr>
              <td>CodeLLDB</td>
              <td><code>vadimcn.vscode-lldb</code></td>
              <td>Rust debugging</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>Recommended <code>.vscode/settings.json</code>:</p>
      <CodeBlock
        language="yaml"
        filename=".vscode/settings.json"
        code={`{
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.cargo.features": "all",
  "[go]": { "editor.defaultFormatter": "golang.go" },
  "[rust]": { "editor.defaultFormatter": "rust-lang.rust-analyzer" },
  "[typescript]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
  "[typescriptreact]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
  "[python]": { "editor.defaultFormatter": "ms-python.python" }
}`}
      />

      <h3>JetBrains (GoLand / RustRover)</h3>
      <ul>
        <li>
          <strong>GoLand</strong>: open <code>apiguard/</code> as a Go project, install the Rust
          plugin, enable golangci-lint under Settings → Go → Linters.
        </li>
        <li>
          <strong>RustRover</strong>: open <code>apiguard/rust/</code> as a Rust project, install
          the Go plugin, enable Clippy on save under Settings → Languages &amp; Frameworks → Rust.
        </li>
        <li>
          Both IDEs: enable "Format on save", connect the Database tool to{' '}
          <code>localhost:5432</code> with credentials from <code>.env</code>, and connect Docker
          integration to the local daemon.
        </li>
      </ul>

      <h2 id="troubleshooting">Troubleshooting</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Problem</th>
              <th>Solution</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Port 5432 already in use</td>
              <td>Stop local PostgreSQL: <code>sudo systemctl stop postgresql</code></td>
            </tr>
            <tr>
              <td>Port 8080 already in use</td>
              <td>Set <code>APIGUARD_PORT</code> to a free port in <code>.env</code></td>
            </tr>
            <tr>
              <td>Docker out of disk space</td>
              <td><code>docker system prune -a</code></td>
            </tr>
            <tr>
              <td>Rust build fails</td>
              <td><code>rustup update stable</code></td>
            </tr>
            <tr>
              <td>Go module issues</td>
              <td><code>go mod tidy</code></td>
            </tr>
          </tbody>
        </table>
      </div>
    </DocsLayout>
  )
}
