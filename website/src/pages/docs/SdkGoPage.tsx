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

export default function SdkGoPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDK', 'Go']}
      toc={toc}
      editPath="SdkGoPage.tsx"
      prev={{ label: 'Evidence & Audit', path: '/docs/citadel/evidence' }}
      next={{ label: 'Python', path: '/docs/sdk/python' }}
    >
      <h1>Go SDK</h1>
      <p>
        The Go client provides typed clients for <strong><a href="/docs/platforms/apiguard">APIGuard</a></strong>,{' '}
        <strong><a href="/docs/platforms/nis2compass">NIS2 Compass</a></strong>, and <strong><a href="/docs/governance">CITADEL</a></strong>, plus shared types for
        all opensecstack <a href="/docs/contracts">SDK &amp; Contracts</a> integration contracts. It requires <strong>Go 1.22+</strong> and
        has <strong>zero external dependencies</strong> — only the standard library.
      </p>

      <h2 id="installation">Installation</h2>
      <p>
        Add the module to your project with <code>go get</code>:
      </p>
      <CodeBlock
        language="bash"
        code={`go get github.com/opensecstack/sdk/go/opensecstack@latest`}
      />
      <p>
        Import the package in your code:
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`import "github.com/opensecstack/sdk/go/opensecstack"`}
      />

      <h2 id="client-construction">Client construction</h2>
      <p>
        Each platform has a dedicated constructor that takes a base URL and an API key.
        Clients are safe to reuse across goroutines.
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`// APIGuard client
apiguard := opensecstack.NewAPIGuardClient(
    "https://apiguard.internal",
    "ag_key_...",
)

// NIS2 Compass client
nis2 := opensecstack.NewNIS2CompassClient(
    "https://nis2compass.internal",
    "nc_key_...",
)

// CITADEL client (HMAC-SHA256 signed)
citadel := opensecstack.NewCITADELClient(opensecstack.CITADELClientOptions{
    BaseURL:      "https://citadel.internal",
    SharedSecret: "hmac-secret",
})
defer citadel.Drain(context.Background()) // flush in-flight events on shutdown`}
      />

      <h2 id="running-a-scan">Running a scan</h2>
      <p>
        Start an APIGuard scan against an OpenAPI spec URL, poll until it completes, then
        retrieve critical findings. Scans run asynchronously on the server — poll{' '}
        <code>GetScan</code> until the status reaches a terminal state.
      </p>
      <CodeBlock
        language="go"
        filename="scan.go"
        code={`// Start scan — simple form
scan, err := apiguard.CreateScan(ctx, "https://api.example.com/openapi.json")
if err != nil {
    return err
}
fmt.Println("Scan ID:", scan.ID)

// Poll until complete
for {
    scan, err = apiguard.GetScan(ctx, scan.ID)
    if err != nil {
        return err
    }
    if scan.Status == opensecstack.ScanStatusCompleted ||
        scan.Status == opensecstack.ScanStatusFailed {
        break
    }
    fmt.Printf("  ... status: %s\\n", scan.Status)
    time.Sleep(5 * time.Second)
}

// Retrieve only critical findings
findings, err := apiguard.GetFindings(ctx, scan.ID, opensecstack.GetFindingsOptions{
    Severity: "critical",
})
if err != nil {
    return err
}

for _, finding := range findings {
    fmt.Printf("[%s] %s — %s %s\\n",
        finding.Severity, finding.Title,
        finding.EndpointMethod, finding.EndpointPath)
}`}
      />
      <p>
        For advanced scan configuration (custom modules, bearer auth, spec path override),
        use <code>CreateScanFull</code>:
      </p>
      <CodeBlock
        language="go"
        filename="scan.go"
        code={`scan, err := apiguard.CreateScanFull(ctx, opensecstack.CreateScanOptions{
    SpecURL:   "https://api.example.com/openapi.json",
    Target:    "https://api.example.com",
    Modules:   []string{"owasp-api1", "owasp-api2", "owasp-api3"},
    AuthType:  "bearer",
    AuthToken: "my-test-token",
})`}
      />

      <h2 id="nis2-compass-client">NIS2 Compass client</h2>
      <p>
        Create an organisation, run an assessment, and mark a NIS2 Article 21 control as
        compliant after gathering evidence from an APIGuard scan.
      </p>
      <CodeBlock
        language="go"
        filename="nis2.go"
        code={`// Create organisation
org, err := nis2.CreateOrganisation(ctx, opensecstack.CreateOrganisationRequest{
    Name:       "Acme Corp",
    Industry:   "finance",
    Country:    "AL",
    Size:       "large",
    EntityType: "essential",
})

// Create assessment — 10 NIS2 Article 21(2) controls (a–j) are seeded automatically
assessment, err := nis2.CreateAssessment(ctx, org.ID, opensecstack.CreateAssessmentRequest{
    Title:            "Q1 2026 NIS2 Assessment",
    FrameworkVersion: "NIS2-2022/0383",
})

// Upload an evidence artifact (e.g. a SARIF report from APIGuard)
artifact, err := nis2.UploadArtifact(ctx, assessment.ID,
    "/tmp/apiguard-report.sarif", "evidence", "", "APIGuard scan evidence")

// Mark control 'e' (security in network and information systems) as compliant
ctrl, err := nis2.PatchControl(ctx, assessment.ID, "e", opensecstack.PatchControlRequest{
    Status: "compliant",
    Notes:  "APIGuard scan completed — zero critical findings",
})
fmt.Printf("Control %s (%s): %s\\n", ctrl.MeasureRef, ctrl.ArticleRef, ctrl.Status)

// Generate a PDF compliance report
pdf, err := nis2.GenerateReport(ctx, assessment.ID)
if err != nil {
    return err
}
os.WriteFile("nis2-report.pdf", pdf, 0644)`}
      />

      <h2 id="citadel-client">CITADEL client</h2>
      <p>
        The CITADEL client delivers structured security events to the immutable <a href="/docs/citadel/worm">WORM</a> audit
        chain via HMAC-SHA256 signed HTTP POST. <code>SendEvent</code> is non-blocking — it
        enqueues the event and a background goroutine handles delivery.
      </p>
      <CodeBlock
        language="go"
        filename="citadel.go"
        code={`// Dispatch an event (non-blocking)
citadel.SendEvent(ctx, opensecstack.SecurityEvent{
    EventType:    "apiguard.scan.completed",
    Source:       "apiguard",
    ActorID:      apiKeyID,
    ActorType:    "api_key",
    ResourceType: "scan",
    ResourceID:   scan.ID,
    Severity:     "info",
    Payload:      json.RawMessage(\`{"total_findings":3}\`),
})

// Query the WORM audit chain
events, err := citadel.GetEvents(ctx, opensecstack.GetEventsOptions{
    Source:    "apiguard",
    EventType: "apiguard.scan.completed",
    Limit:     50,
})

// Verify the chain integrity locally (TripleHash: SHA-256 + SHA-512 + BLAKE3)
err = citadel.VerifyChain(ctx, events)`}
      />

      <h2 id="error-handling">Error handling</h2>
      <p>
        All clients return typed errors. Use <code>errors.As</code> to inspect the specific
        error type and act accordingly (for example, back off on rate-limit errors).
      </p>
      <CodeBlock
        language="go"
        filename="errors.go"
        code={`scan, err := apiguard.CreateScanFull(ctx, opensecstack.CreateScanOptions{
    SpecURL: "https://api.example.com/openapi.json",
})
if err != nil {
    var rateLimitErr *opensecstack.RateLimitError
    if errors.As(err, &rateLimitErr) {
        time.Sleep(rateLimitErr.RetryAfter)
        // retry ...
    }
    return err
}`}
      />
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Error type</th>
              <th>HTTP status</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>*opensecstack.AuthError</code></td>
              <td>401</td>
              <td>Invalid API key</td>
            </tr>
            <tr>
              <td><code>*opensecstack.NotFoundError</code></td>
              <td>404</td>
              <td>Resource not found</td>
            </tr>
            <tr>
              <td><code>*opensecstack.RateLimitError</code></td>
              <td>429</td>
              <td>Rate limit hit; has <code>RetryAfter</code> field</td>
            </tr>
            <tr>
              <td><code>*opensecstack.ServerError</code></td>
              <td>5xx</td>
              <td>Server-side error</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        Other SDK language clients: <a href="/docs/sdk/python">Python SDK</a>,{' '}
        <a href="/docs/sdk/typescript">TypeScript SDK</a>,{' '}
        <a href="/docs/sdk/rust">Rust SDK</a>.
      </p>
      <p>
        The complete Go client reference — including all method signatures, option structs,
        and type definitions — is available in the SDK repository:
      </p>
      <p>
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sdk" target="_blank" rel="noopener noreferrer">
          https://github.com/opensecstack/opensecstack/tree/main/sdk
        </a>
      </p>
    </DocsLayout>
  )
}
