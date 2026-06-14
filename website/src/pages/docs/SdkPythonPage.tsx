import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'installation', label: 'Installation' },
  { id: 'client-construction', label: 'Client construction' },
  { id: 'running-a-scan', label: 'Running a scan' },
  { id: 'nis2-compass-client', label: 'NIS2 Compass client' },
  { id: 'citadel-client', label: 'CITADEL client' },
  { id: 'error-handling', label: 'Error handling' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function SdkPythonPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDK', 'Python']}
      toc={toc}
      editPath="SdkPythonPage.tsx"
      prev={{ label: 'Go', path: '/docs/sdk/go' }}
      next={{ label: 'TypeScript', path: '/docs/sdk/typescript' }}
    >
      <h1>Python SDK</h1>
      <p>
        The Python client provides typed clients for <strong><a href="/docs/platforms/apiguard">APIGuard</a></strong>,{' '}
        <strong><a href="/docs/platforms/nis2compass">NIS2 Compass</a></strong>, and <strong><a href="/docs/governance">CITADEL</a></strong>, plus dataclasses for
        all opensecstack <a href="/docs/contracts">SDK &amp; Contracts</a> integration contracts. It requires <strong>Python 3.11+</strong>.
        Both synchronous and async clients are available.
      </p>

      <h2 id="installation">Installation</h2>
      <p>
        Install the package from PyPI:
      </p>
      <CodeBlock
        language="bash"
        code={`pip install opensecstack`}
      />
      <p>
        Import the clients you need:
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack import APIGuardClient, NIS2CompassClient
from opensecstack.citadel import CITADELClient, Kerkese, Action, Principal, Evidence`}
      />

      <h2 id="client-construction">Client construction</h2>
      <p>
        Clients accept a <code>base_url</code> and an <code>api_key</code>. An optional
        <code> timeout</code> (in seconds) can be passed; the default is 30&nbsp;s. Clients
        support use as context managers to ensure the underlying session is closed.
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack import APIGuardClient

# Standard usage
client = APIGuardClient(
    base_url="https://apiguard.internal",
    api_key="ag_key_...",
    timeout=30,
)

# Context manager — session closed automatically on exit
with APIGuardClient(base_url="https://apiguard.internal", api_key="ag_key_...") as client:
    result = client.get_scan(scan_id)`}
      />

      <h2 id="running-a-scan">Running a scan</h2>
      <p>
        Start an APIGuard scan and use the blocking <code>wait_for_scan</code> helper to
        poll until the scan completes, then iterate over the findings.
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack import APIGuardClient

client = APIGuardClient(base_url="https://apiguard.internal", api_key="ag_key_...")

# Start scan with selected OWASP modules
scan = client.start_scan(
    target="https://api.example.com",
    spec_url="https://api.example.com/openapi.json",
    modules=["bola", "broken_auth", "injection"],
    metadata={"project": "my-project-001"},
)
print(f"Scan ID: {scan.id}")

# Block until complete (polls every 5 s, times out after 600 s)
result = client.wait_for_scan(
    scan_id=scan.id,
    poll_interval=5,
    timeout=600,
)

for finding in result.findings:
    print(f"[{finding.severity}] {finding.owasp} — {finding.title}")`}
      />
      <p>
        An async client is also available for non-blocking workflows:
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack import AsyncAPIGuardClient

async with AsyncAPIGuardClient(
    base_url="https://apiguard.internal",
    client_id="...",
    client_secret="...",
) as client:
    scan = await client.create_scan(spec_url="https://api.example.com/openapi.json")
    result = await client.get_scan(scan["id"])`}
      />

      <h2 id="nis2-compass-client">NIS2 Compass client</h2>
      <p>
        Create an assessment, list its controls, and mark a NIS2 Article 21 measure as
        compliant after uploading evidence from an APIGuard scan.
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack import NIS2CompassClient

nis2 = NIS2CompassClient(base_url="https://nis2compass.internal", api_key="nc_key_...")

# Create organisation
org = nis2.create_organisation(
    name="Acme Corp",
    industry="finance",
    country="AL",
    size="large",
    entity_type="essential",
)

# Create assessment
assessment = nis2.create_assessment(
    org_id=org.id,
    title="Q1 2026 NIS2 Assessment",
    framework_version="NIS2-2022/0383",
)

# List controls and print current status
assessment = nis2.get_assessment(org.id, assessment.id)
for control in assessment.controls:
    print(f"{control.measure_ref}: {control.status}")

# Mark control art21_e as compliant
updated = nis2.patch_control(
    org_id=org.id,
    assessment_id=assessment.id,
    measure_ref="art21_e",
    status="compliant",
    notes="APIGuard scan completed — zero critical findings",
    evidence_refs=["sha256:abc123..."],
)`}
      />

      <h2 id="citadel-client">CITADEL client</h2>
      <p>
        Submit a governance <em>Kerkese</em> request to the <a href="/docs/citadel/marshal">MARSHAL</a> 5-gate engine and check
        the outcome before proceeding with a privileged action.
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack.citadel import CITADELClient, Kerkese, Action, Principal, Evidence

client = CITADELClient(
    base_url="https://citadel.internal",
    key_id=KEY_ID,
    secret=SECRET,
)

# Check for active advisories before acting
advisory = client.get_advisory("my-project-001", "deploy_change")
if advisory.has_critical():
    print(f"CITADEL advisory: {advisory.advisories}")

# Submit a governance request and evaluate
result = client.evaluate(Kerkese(
    project_id="my-project-001",
    action=Action(type="deploy_change", description="Deploy v2.1.0"),
    actor=Principal(user_id="alice@example.com", role="group_sig_operator"),
    verifier=Principal(user_id="bob@example.com", role="group_sig_verifier"),
    evidence=Evidence(change_id="CHG-001"),
))

if result["outcome"] != "EXECUTE":
    raise RuntimeError(f"Governance denied: {result['reasons']}")`}
      />

      <h2 id="error-handling">Error handling</h2>
      <p>
        Import exception types from <code>opensecstack.exceptions</code> to handle specific
        failure modes. <code>RateLimitError</code> carries a <code>retry_after</code>{' '}
        attribute (seconds) to guide back-off logic.
      </p>
      <CodeBlock
        language="bash"
        code={`from opensecstack.exceptions import RateLimitError, AuthError, NotFoundError
import time

try:
    result = client.start_scan(
        target="https://api.example.com",
        spec_url="https://api.example.com/openapi.json",
    )
except RateLimitError as e:
    time.sleep(e.retry_after)
    result = client.start_scan(...)  # retry
except AuthError:
    raise  # re-raise — fix the API key
except NotFoundError:
    raise`}
      />
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Exception</th>
              <th>HTTP status</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>AuthError</code></td>
              <td>401</td>
              <td>Invalid API key</td>
            </tr>
            <tr>
              <td><code>NotFoundError</code></td>
              <td>404</td>
              <td>Resource not found</td>
            </tr>
            <tr>
              <td><code>RateLimitError</code></td>
              <td>429</td>
              <td>Rate limited; has <code>retry_after</code> attribute</td>
            </tr>
            <tr>
              <td><code>ServerError</code></td>
              <td>5xx</td>
              <td>Server-side error</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        Other SDK language clients: <a href="/docs/sdk/go">Go SDK</a>,{' '}
        <a href="/docs/sdk/typescript">TypeScript SDK</a>,{' '}
        <a href="/docs/sdk/rust">Rust SDK</a>.
      </p>
      <p>
        The complete Python client reference — including all method signatures, dataclass
        definitions, and type hints — is available in the SDK repository:
      </p>
      <p>
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sdk" target="_blank" rel="noopener noreferrer">
          https://github.com/opensecstack/opensecstack/tree/main/sdk
        </a>
      </p>
    </DocsLayout>
  )
}
