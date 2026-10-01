import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'
import { Link } from 'react-router-dom'

const toc = [
  { id: 'installation', label: 'Installation' },
  { id: 'client-construction', label: 'Client construction' },
  { id: 'running-a-scan', label: 'Running a scan' },
  { id: 'nis2-compass-client', label: 'NIS2 Compass client' },
  { id: 'error-handling', label: 'Error handling' },
  { id: 'citadel-kerkese-core', label: 'CITADEL MARSHAL (Kerkese)' },
  { id: 'security-notes', label: 'Security notes' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function SdkRustPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDK', 'Rust']}
      toc={toc}
      editPath="SdkRustPage.tsx"
      prev={{ label: 'TypeScript', path: '/docs/sdk/typescript' }}
      next={{ label: 'NIS2 & EU AI Act', path: '/docs/nis2' }}
    >
      <Helmet>
        <title>Rust SDK | opensecstack Docs</title>
        <meta
          name="description"
          content="The opensecstack Rust SDK provides async, type-safe clients for APIGuard and NIS2 Compass built on tokio and reqwest, requiring Rust 1.75+."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/sdk/rust" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/sdk/rust" />
        <meta property="og:title" content="Rust SDK | opensecstack Docs" />
        <meta
          property="og:description"
          content="The opensecstack Rust SDK provides async, type-safe clients for APIGuard and NIS2 Compass built on tokio and reqwest, requiring Rust 1.75+."
        />
      </Helmet>
      <h1>Rust SDK</h1>
      <p>
        The Rust client provides async, type-safe clients for <strong><Link to="/docs/platforms/apiguard">APIGuard</Link></strong> and{' '}
        <strong><Link to="/docs/platforms/nis2compass">NIS2 Compass</Link></strong> built on <strong>tokio</strong> +{' '}
        <strong>reqwest</strong>, with <code>serde</code> for JSON,{' '}
        <code>thiserror</code> for structured errors, and a builder pattern for client
        configuration. It requires <strong>Rust 1.75+</strong> (stable).
        See <Link to="/docs/contracts">SDK &amp; Contracts</Link> for the full integration contract reference.
      </p>

      <h2 id="installation">Installation</h2>
      <p>
        Add the crate and the <code>tokio</code> async runtime to your{' '}
        <code>Cargo.toml</code>:
      </p>
      <CodeBlock
        language="bash"
        code={`cargo add opensecstack
cargo add tokio --features full`}
      />
      <p>
        Or edit <code>Cargo.toml</code> directly:
      </p>
      <CodeBlock
        language="yaml"
        filename="Cargo.toml"
        code={`[dependencies]
opensecstack = "0.1"
tokio = { version = "1", features = ["full"] }`}
      />

      <h2 id="client-construction">Client construction</h2>
      <p>
        Use the <code>::new</code> constructor for sensible defaults (30&nbsp;s timeout,
        2 retries, rustls TLS), or the builder for custom settings.
      </p>
      <CodeBlock
        language="bash"
        code={`use opensecstack::APIGuardClient;
use std::time::Duration;

// Default settings
let client = APIGuardClient::new(
    "https://apiguard.internal",
    "ak_live_...",
);

// Custom settings via builder
let client = APIGuardClient::builder("https://apiguard.internal", "ak_live_...")
    .timeout(Duration::from_secs(60))
    .max_retries(3)
    .retry_wait_base(Duration::from_millis(250))
    .build();`}
      />

      <h2 id="running-a-scan">Running a scan</h2>
      <p>
        Start a scan asynchronously, poll until it reaches a terminal status, then retrieve
        and print critical findings. All async functions must be <code>.await</code>ed
        inside a <code>#[tokio::main]</code> context.
      </p>
      <CodeBlock
        language="bash"
        code={`use opensecstack::{APIGuardClient, CreateScanOptions, ScanStatus,
                   GetFindingsOptions, FindingSeverity};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = APIGuardClient::new("https://apiguard.internal", "ak_live_...");

    // Start scan
    let scan = client.create_scan("https://api.example.com/openapi.json").await?;
    println!("Scan ID: {}", scan.id);

    // Poll until complete
    let completed = loop {
        sleep(Duration::from_secs(5)).await;
        let s = client.get_scan(&scan.id).await?;
        match s.status {
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => break s,
            _ => {}
        }
    };
    println!("{} findings", completed.total_findings);

    // Retrieve critical findings
    let findings = client.get_findings(&scan.id, Some(GetFindingsOptions {
        severity: Some(FindingSeverity::Critical),
        ..Default::default()
    })).await?;

    for f in &findings {
        println!("[{}] {} {} — {}", f.owasp_id, f.endpoint_method, f.endpoint_path, f.title);
    }

    Ok(())
}`}
      />
      <p>
        Use <code>create_scan_full</code> to configure modules, target URL, and
        authentication:
      </p>
      <CodeBlock
        language="bash"
        code={`use opensecstack::CreateScanOptions;

let scan = client.create_scan_full(CreateScanOptions {
    target_url: "https://api.example.com".to_string(),
    spec_url: Some("https://api.example.com/openapi.json".to_string()),
    modules: vec!["bola".to_string(), "broken_auth".to_string(), "injection".to_string()],
    auth_type: Some("bearer".to_string()),
    auth_token: Some("eyJhb...".to_string()),
    ..Default::default()
}).await?;`}
      />

      <h2 id="nis2-compass-client">NIS2 Compass client</h2>
      <p>
        Manage organisations and <Link to="/docs/nis2">NIS2</Link> assessments. Controls follow NIS2 Article 21(2) and
        are identified by letters <code>'a'</code> through <code>'j'</code>. Audit log
        entries include a tamper-evident hash chain (<code>prev_hash</code> /{' '}
        <code>chain_hash</code>).
      </p>
      <CodeBlock
        language="bash"
        code={`use opensecstack::{NIS2CompassClient, CreateOrganisationRequest, OrganisationSize,
                   CreateAssessmentRequest, PatchControlRequest, ControlStatus,
                   ArtifactType};

let client = NIS2CompassClient::new("https://nis2compass.internal", "nk_live_...");

// Create organisation
let org = client.create_organisation(CreateOrganisationRequest {
    name: "Example GmbH".to_string(),
    industry: Some("financial_services".to_string()),
    country: Some("DE".to_string()),
    size: Some(OrganisationSize::Medium),
    registration_number: Some("HRB 123456 B".to_string()),
}).await?;

// Create assessment
let assessment = client.create_assessment(
    &org.id.to_string(),
    CreateAssessmentRequest {
        title: "NIS2 Annual Assessment 2026".to_string(),
        scope: Some("All production systems".to_string()),
        assessor: Some("ciso@example.de".to_string()),
        due_date: Some("2026-12-31".to_string()),
    },
).await?;

// Mark control 'a' as compliant with evidence
let updated = client.patch_control(
    &assessment.id.to_string(),
    'a',
    PatchControlRequest {
        status: Some(ControlStatus::Compliant),
        evidence: Some(serde_json::json!({
            "document_ref": "IS-POL-001",
            "approved_by": "CISO",
            "approved_at": "2026-01-15"
        })),
        risk_score: Some(2.5),
        ..Default::default()
    },
).await?;

// Upload evidence artifact tied to the control
let artifact = client.upload_artifact(
    &assessment.id.to_string(),
    "/path/to/security_policy.pdf",
    ArtifactType::Policy,
    Some(&updated.id.to_string()),
    Some("Information Security Policy v3.0"),
).await?;
println!("Artifact: {} ({} bytes)", artifact.filename, artifact.size_bytes);`}
      />

      <h2 id="error-handling">Error handling</h2>
      <p>
        The crate exposes a single <code>Error</code> enum with variants for every failure
        mode. Match on it in your error-handling code to implement targeted recovery (for
        example, respecting <code>retry_after</code> on 429 responses).
      </p>
      <CodeBlock
        language="bash"
        code={`use opensecstack::Error;

match result {
    Err(Error::NotFound(path))            => { /* 404 */ }
    Err(Error::RateLimit { retry_after }) => { /* 429 — back off */ }
    Err(Error::Auth(msg))                 => { /* bad API key */ }
    Err(Error::Api { status, code, .. })  => { /* structured API error */ }
    Err(Error::Transport(e))              => { /* network failure */ }
    Err(Error::Json(e))                   => { /* parse failure */ }
    Err(Error::Io(e))                     => { /* file I/O failure */ }
    _ => {}
}`}
      />

      <h2 id="citadel-kerkese-core">CITADEL MARSHAL (Kerkese)</h2>
      <p>
        <code>opensecstack::citadel::CITADELClient</code> (above) is a WORM{' '}
        <em>event-delivery</em> client — <code>send_event</code>/<code>get_events</code>/
        <code>verify_chain</code> — it does not submit a Kerkese for{' '}
        <Link to="/docs/governance">MARSHAL</Link> evaluation. That's a separate crate,{' '}
        <strong><code>citadel-kerkese-core</code></strong>, published from the same{' '}
        <code>sdk/rust/</code> directory: a <code>no_std</code> + <code>alloc</code> core for
        building, Ed25519-signing, and submitting CITADEL MARSHAL Kerkese requests, for hosts
        that can't pull in Tokio/reqwest at all (a freestanding kernel being the motivating
        case). It does no networking of its own — a <code>KerkeseTransport</code> trait is the
        host-supplied I/O boundary, so the same core works both from a freestanding kernel and
        from a hosted <code>std</code> process via a <code>reqwest</code>-backed transport.
      </p>
      <CodeBlock
        language="bash"
        code={`[dependencies]
citadel-kerkese-core = "1.0.0"`}
      />
      <p>
        See <code>sdk/rust/citadel-kerkese-core</code>'s own README and{' '}
        <code>examples/</code> for the full API and a worked <code>std</code> transport
        example.
      </p>

      <h2 id="security-notes">Security notes</h2>
      <ul>
        <li>
          <strong>No redirect following:</strong> HTTP redirect following is disabled on all
          clients (SDK-M4) to prevent Bearer tokens from leaking to redirect targets.
        </li>
        <li>
          <strong>Proactive token refresh:</strong> JWT <code>exp</code> is parsed from the
          token payload; the SDK refreshes tokens 60&nbsp;seconds before expiry to prevent
          mid-flight failures (SDK-M5).
        </li>
        <li>
          <strong>TLS:</strong> Uses <code>rustls</code> exclusively — <code>native-tls</code>{' '}
          is not a dependency.
        </li>
        <li>
          <strong>No secrets in logs:</strong> The SDK never logs API keys or access tokens;
          tracing calls include only method, path, and status code at DEBUG level.
        </li>
      </ul>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        Other SDK language clients: <Link to="/docs/sdk/go">Go SDK</Link>,{' '}
        <Link to="/docs/sdk/python">Python SDK</Link>,{' '}
        <Link to="/docs/sdk/typescript">TypeScript SDK</Link>.
      </p>
      <p>
        The complete Rust client reference — including all type definitions, builder
        options, shared types, and runnable examples — is available in the SDK repository:
      </p>
      <p>
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sdk" target="_blank" rel="noopener noreferrer">
          https://github.com/opensecstack/opensecstack/tree/main/sdk
        </a>
      </p>
    </DocsLayout>
  )
}
